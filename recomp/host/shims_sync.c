// Handles, threads and synchronisation: events, semaphores, mutexes, critical sections, waits.
// Each guest thread is a host pthread running recompiled code on its own CPU + stack + TEB.
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "shims.h"

// ---- handle table ----------------------------------------------------------------------------
#define MAXH 65536
static struct { int type; void *obj; } htab[MAXH];
static pthread_mutex_t hlock = PTHREAD_MUTEX_INITIALIZER;
uint32_t handle_new(int type, void *obj) {
    pthread_mutex_lock(&hlock);
    for (uint32_t i = 64; i < MAXH; i++)
        if (!htab[i].type) { htab[i].type = type; htab[i].obj = obj; pthread_mutex_unlock(&hlock); return i * 4; }
    pthread_mutex_unlock(&hlock);
    return 0;
}
void *handle_get(uint32_t h, int type) {
    uint32_t i = h / 4;
    return i < MAXH && htab[i].type == type ? htab[i].obj : NULL;
}
int handle_type(uint32_t h) { uint32_t i = h / 4; return i < MAXH ? htab[i].type : 0; }
void handle_close(uint32_t h) { uint32_t i = h / 4; if (i < MAXH) { htab[i].type = 0; htab[i].obj = NULL; } }

// ---- waitable objects ------------------------------------------------------------------------
typedef struct {
    pthread_mutex_t m; pthread_cond_t cv;
    int manual, signaled;          // event
    int count, max;                // semaphore
    pthread_t owner; int recursion; int owned;  // mutex
    int done; uint32_t exit_code;  // thread
    int suspend;                   // thread: >0 while suspended (CREATE_SUSPENDED / SuspendThread)
} Obj;

static Obj *obj_new(void) {
    Obj *o = calloc(1, sizeof *o);
    pthread_mutex_init(&o->m, NULL);
    pthread_cond_init(&o->cv, NULL);
    return o;
}

// is the object signaled for the calling thread? (called with o->m held); consumes if it can
static int try_acquire(int type, Obj *o) {
    switch (type) {
    case H_EVENT: if (o->signaled) { if (!o->manual) o->signaled = 0; return 1; } return 0;
    case H_SEMA: if (o->count > 0) { o->count--; return 1; } return 0;
    case H_MUTEX:
        if (!o->owned || pthread_equal(o->owner, pthread_self())) { o->owned = 1; o->owner = pthread_self(); o->recursion++; return 1; }
        return 0;
    case H_THREAD: return o->done;
    }
    return 1;
}

static void deadline(struct timespec *ts, uint32_t ms) {
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

// 0 = WAIT_OBJECT_0, 0x102 = WAIT_TIMEOUT
static uint32_t wait_one(uint32_t h, uint32_t ms) {
    int t = handle_type(h);
    Obj *o = t ? handle_get(h, t) : NULL;
    if (!o) return 0xFFFFFFFFu;
    struct timespec ts; deadline(&ts, ms);
    pthread_mutex_lock(&o->m);
    while (!try_acquire(t, o)) {
        if (ms == 0) { pthread_mutex_unlock(&o->m); return 0x102; }
        int r = ms == 0xFFFFFFFFu ? pthread_cond_wait(&o->cv, &o->m) : pthread_cond_timedwait(&o->cv, &o->m, &ts);
        if (r == ETIMEDOUT) { pthread_mutex_unlock(&o->m); return 0x102; }
    }
    pthread_mutex_unlock(&o->m);
    return 0;
}

SHIM(CreateEventA) {
    Obj *o = obj_new(); o->manual = (int)ARG(c, 1); o->signaled = (int)ARG(c, 2);
    RET(c, handle_new(H_EVENT, o), 4);
}
SHIM(SetEvent) {
    Obj *o = handle_get(ARG(c, 0), H_EVENT);
    if (o) { pthread_mutex_lock(&o->m); o->signaled = 1; pthread_cond_broadcast(&o->cv); pthread_mutex_unlock(&o->m); }
    RET(c, o != NULL, 1);
}
SHIM(ResetEvent) {
    Obj *o = handle_get(ARG(c, 0), H_EVENT);
    if (o) { pthread_mutex_lock(&o->m); o->signaled = 0; pthread_mutex_unlock(&o->m); }
    RET(c, o != NULL, 1);
}
SHIM(CreateSemaphoreA) { Obj *o = obj_new(); o->count = (int)ARG(c, 1); o->max = (int)ARG(c, 2); RET(c, handle_new(H_SEMA, o), 4); }
SHIM(ReleaseSemaphore) {
    Obj *o = handle_get(ARG(c, 0), H_SEMA); uint32_t prev = ARG(c, 2);
    if (!o) { RET(c, 0, 3); return; }
    pthread_mutex_lock(&o->m);
    if (prev) P32(prev, (uint32_t)o->count);
    o->count += (int)ARG(c, 1);
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->m);
    RET(c, 1, 3);
}
SHIM(CreateMutexA) {
    Obj *o = obj_new();
    if (ARG(c, 1)) { o->owned = 1; o->owner = pthread_self(); o->recursion = 1; }
    RET(c, handle_new(H_MUTEX, o), 3);
}
SHIM(WaitForSingleObject) { RET(c, wait_one(ARG(c, 0), ARG(c, 1)), 2); }
SHIM(WaitForMultipleObjects) {
    uint32_t n = ARG(c, 0), arr = ARG(c, 1), all = ARG(c, 2), ms = ARG(c, 3);
    struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {      // simple polling implementation: correct, not fast; revisit if it shows up in profiles
        if (all) {
            uint32_t ok = 1;
            for (uint32_t i = 0; i < n; i++) ok &= wait_one(G32(arr + 4 * i), 0) == 0;
            if (ok) { RET(c, 0, 4); return; }
        } else {
            for (uint32_t i = 0; i < n; i++) if (wait_one(G32(arr + 4 * i), 0) == 0) { RET(c, i, 4); return; }
        }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t el = (uint64_t)(now.tv_sec - start.tv_sec) * 1000 + (uint64_t)(now.tv_nsec - start.tv_nsec) / 1000000;
        if (ms != 0xFFFFFFFFu && el >= ms) { RET(c, 0x102, 4); return; }
        usleep(200);
    }
}

// ---- critical sections: guest address -> host recursive mutex ---------------------------------
#define CS_BUCKETS 4096
typedef struct CSNode { uint32_t addr; pthread_mutex_t m; struct CSNode *next; } CSNode;
static CSNode *cs_tab[CS_BUCKETS];
static pthread_mutex_t cs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *cs_get(uint32_t a) {
    uint32_t b = (a >> 3) % CS_BUCKETS;
    pthread_mutex_lock(&cs_lock);
    CSNode *n = cs_tab[b];
    while (n && n->addr != a) n = n->next;
    if (!n) {
        n = calloc(1, sizeof *n); n->addr = a;
        pthread_mutexattr_t at; pthread_mutexattr_init(&at); pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&n->m, &at);
        n->next = cs_tab[b]; cs_tab[b] = n;
    }
    pthread_mutex_unlock(&cs_lock);
    return &n->m;
}
SHIM(InitializeCriticalSection) { memset(MEM + ARG(c, 0), 0, 24); cs_get(ARG(c, 0)); RET(c, 0, 1); }
SHIM(InitializeCriticalSectionAndSpinCount) { memset(MEM + ARG(c, 0), 0, 24); cs_get(ARG(c, 0)); RET(c, 1, 2); }
SHIM(DeleteCriticalSection) { RET(c, 0, 1); }
SHIM(EnterCriticalSection) { pthread_mutex_lock(cs_get(ARG(c, 0))); RET(c, 0, 1); }
SHIM(LeaveCriticalSection) { pthread_mutex_unlock(cs_get(ARG(c, 0))); RET(c, 0, 1); }
SHIM(TryEnterCriticalSection) { RET(c, pthread_mutex_trylock(cs_get(ARG(c, 0))) == 0, 1); }

// interlocked: real atomics on guest memory
#define A32(a) ((_Atomic uint32_t *)(void *)(MEM + (a)))
SHIM(InterlockedIncrement) { RET(c, __atomic_add_fetch((uint32_t *)(MEM + ARG(c, 0)), 1, __ATOMIC_SEQ_CST), 1); }
SHIM(InterlockedDecrement) { RET(c, __atomic_sub_fetch((uint32_t *)(MEM + ARG(c, 0)), 1, __ATOMIC_SEQ_CST), 1); }
SHIM(InterlockedExchange) { RET(c, __atomic_exchange_n((uint32_t *)(MEM + ARG(c, 0)), ARG(c, 1), __ATOMIC_SEQ_CST), 2); }
SHIM(InterlockedExchangeAdd) { RET(c, __atomic_fetch_add((uint32_t *)(MEM + ARG(c, 0)), ARG(c, 1), __ATOMIC_SEQ_CST), 2); }
SHIM(InterlockedCompareExchange) {
    uint32_t exp = ARG(c, 2);
    __atomic_compare_exchange_n((uint32_t *)(MEM + ARG(c, 0)), &exp, ARG(c, 1), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    RET(c, exp, 3);
}

// ---- threads ---------------------------------------------------------------------------------
typedef struct { uint32_t start, param; Obj *obj; uint32_t tid; } ThreadStart;
static uint32_t next_tid = 2;
extern int host_run_guest(CPU *c, uint32_t entry);   // host.c: trap-guarded call

static void *thread_main(void *p) {
    ThreadStart *ts = p;
    pthread_mutex_lock(&ts->obj->m);                      // CREATE_SUSPENDED: wait for ResumeThread
    while (ts->obj->suspend > 0) pthread_cond_wait(&ts->obj->cv, &ts->obj->m);
    pthread_mutex_unlock(&ts->obj->m);
    CPU *c = calloc(1, sizeof *c);
    host_thread_init(c, 1 << 20);
    P32(REG(c, 272) + 0x24, ts->tid);
    ST(c->r + 4256, 0x027F, 2);
    uint32_t esp = REG(c, R_ESP) - 8;
    P32(esp, HOST_EXIT_THUNK); P32(esp + 4, ts->param);
    SETREG(c, R_ESP, esp);
    host_run_guest(c, ts->start);
    pthread_mutex_lock(&ts->obj->m);
    ts->obj->done = 1; ts->obj->exit_code = REG(c, R_EAX);
    pthread_cond_broadcast(&ts->obj->cv);
    pthread_mutex_unlock(&ts->obj->m);
    return NULL;
}
SHIM(CreateThread) {
    ThreadStart *ts = calloc(1, sizeof *ts);
    ts->start = ARG(c, 2); ts->param = ARG(c, 3); ts->obj = obj_new();
    ts->tid = __atomic_fetch_add(&next_tid, 1, __ATOMIC_SEQ_CST);
    if (ARG(c, 4) & 4) ts->obj->suspend = 1;
    uint32_t h = handle_new(H_THREAD, ts->obj);
    if (ARG(c, 5)) P32(ARG(c, 5), ts->tid);
    fprintf(stderr, "[thread] CreateThread start %#x param %#x flags %#x -> handle %#x tid %u\n", ts->start, ts->param, ARG(c, 4), h, ts->tid);
    pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setstacksize(&at, 64u << 20);
    pthread_t th; pthread_create(&th, &at, thread_main, ts); pthread_detach(th);
    RET(c, h, 6);
}
SHIM(ResumeThread) {
    Obj *o = handle_get(ARG(c, 0), H_THREAD);
    fprintf(stderr, "[thread] ResumeThread(%#x) %s\n", ARG(c, 0), o ? "" : "-> invalid handle");
    if (!o) { RET(c, 0xFFFFFFFFu, 1); return; }
    pthread_mutex_lock(&o->m);
    int prev = o->suspend;
    if (o->suspend > 0) o->suspend--;
    pthread_cond_broadcast(&o->cv);
    pthread_mutex_unlock(&o->m);
    RET(c, (uint32_t)prev, 1);
}
// Suspending a running thread asynchronously is not supported; only the count is tracked.
SHIM(SuspendThread) { Obj *o = handle_get(ARG(c, 0), H_THREAD); RET(c, o ? (uint32_t)o->suspend : 0xFFFFFFFFu, 1); }
SHIM(SetThreadPriority) { RET(c, 1, 2); }
SHIM(SetThreadIdealProcessor) { RET(c, 0, 2); }
SHIM(GetExitCodeThread) {
    Obj *o = handle_get(ARG(c, 0), H_THREAD);
    if (o) P32(ARG(c, 1), o->done ? o->exit_code : 259 /* STILL_ACTIVE */);
    RET(c, o != NULL, 2);
}
SHIM(ExitThread) { fprintf(stderr, "[host] ExitThread(%u)\n", ARG(c, 0)); pthread_exit(NULL); }
SHIM(CloseHandle) {
    uint32_t h = ARG(c, 0);
    if (handle_type(h) == H_THREAD) {
        fprintf(stderr, "[thread] CloseHandle(%#x) thread, caller %#x\n", h, G32(REG(c, R_ESP)));
        static int dumped;
        if (!dumped++) {
            uint32_t sp = REG(c, R_ESP);
            fprintf(stderr, "[thread]   stack:");
            for (int i = 0, n = 0; i < 2048 && n < 24; i++) { uint32_t v = G32(sp + 4 * (uint32_t)i); if (v >= 0x401000 && v < 0xfdf000) { fprintf(stderr, " %#x", v); n++; } }
            fprintf(stderr, "\n");
        }
    }
    handle_close(h); RET(c, 1, 1);
}

SHIM_TABLE(sync_shims,
    E(CreateEventA) E(SetEvent) E(ResetEvent) E(CreateSemaphoreA) E(ReleaseSemaphore) E(CreateMutexA)
    E(WaitForSingleObject) E(WaitForMultipleObjects) E(InitializeCriticalSection)
    E(InitializeCriticalSectionAndSpinCount) E(DeleteCriticalSection) E(EnterCriticalSection)
    E(LeaveCriticalSection) E(TryEnterCriticalSection) E(InterlockedIncrement) E(InterlockedDecrement)
    E(InterlockedExchange) E(InterlockedExchangeAdd) E(InterlockedCompareExchange) E(CreateThread)
    E(ResumeThread) E(SuspendThread) E(SetThreadPriority) E(SetThreadIdealProcessor) E(GetExitCodeThread)
    E(ExitThread) E(CloseHandle))
