// Dumps raw P-code for a set of functions as JSON lines, one function per line:
//   {"entry":int,"name":str,"insns":[{"a":int,"len":int,"m":str,"ops":[[opc,out,[in...]],...]}],
//    "callees":[int...],"leaf":bool}
// A varnode is [space, offset, size]; space is "register", "unique", "ram" or "const".
// Also writes <out>.regs.json mapping register-space offsets to names (for readable C).
//
// Args: <out.jsonl> <mode> [limit]
//   mode = leaf  -> functions with no CALL/CALLIND and no unresolved BRANCHIND
//   mode = all   -> every function
//@category BYOG

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

public class DumpPcode extends GhidraScript {

    private String vn(Varnode v) {
        if (v == null) return "null";
        String sp = v.getAddress().getAddressSpace().getName();
        if (v.isConstant()) sp = "const";
        return "[\"" + sp + "\"," + Long.toUnsignedString(v.getOffset()) + "," + v.getSize() + "]";
    }


    // Body by control flow from the entry, independent of Ghidra's function-body bookkeeping:
    // fall-through, branches and resolved switch targets are followed; a jump to another
    // function's entry is a tail call and stops there; after a CALL the next instruction is
    // included unless the callee is known not to return. Instructions may appear in several
    // functions' bodies (shared tails) — the recompiler emits each copy.
    private final java.util.Map<Function, Boolean> retCache = new java.util.HashMap<>();
    private boolean returns(Function f) {
        if (f == null) return true;
        if (f.isThunk()) f = f.getThunkedFunction(true);
        if (f == null || f.isExternal()) return true;
        final Function g = f;
        return retCache.computeIfAbsent(g, k -> {
            if (!k.hasNoReturn()) return true;
            for (Instruction in : currentProgram.getListing().getInstructions(k.getBody(), true))
                if (in.getFlowType().isTerminal() && in.getMnemonicString().toUpperCase().startsWith("RET")) return true;
            return false;
        });
    }
    private List<Instruction> flowBody(Function f) {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        TreeMap<Long, Instruction> seen = new TreeMap<>();
        ArrayDeque<Address> work = new ArrayDeque<>();
        work.add(f.getEntryPoint());
        while (!work.isEmpty() && seen.size() < 200000) {
            Address a = work.poll();
            if (seen.containsKey(a.getOffset())) continue;
            Instruction in = listing.getInstructionAt(a);
            if (in == null) continue;
            seen.put(a.getOffset(), in);
            FlowType ft = in.getFlowType();
            Address next = in.getMaxAddress().next();
            if (ft.isCall()) {
                boolean ret = true;
                for (Address t : in.getFlows()) ret &= returns(fm.getFunctionAt(t));
                if (ret && next != null) work.add(next);
                continue;
            }
            if (ft.isJump()) {
                for (Address t : in.getFlows())
                    if (!t.equals(f.getEntryPoint()) && fm.getFunctionAt(t) != null) { /* tail call */ }
                    else work.add(t);
                if (ft.isComputed())
                    for (Reference r : in.getReferencesFrom())
                        if (r.getReferenceType().isFlow()) work.add(r.getToAddress());
                if (ft.isConditional() && next != null) work.add(next);
                continue;
            }
            if (ft.isTerminal()) continue;
            if (next != null) work.add(next);
        }
        return new ArrayList<>(seen.values());
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args[0]);
        String mode = args.length > 1 ? args[1] : "leaf";
        int limit = args.length > 2 ? Integer.parseInt(args[2]) : Integer.MAX_VALUE;
        Listing listing = currentProgram.getListing();

        int written = 0, scanned = 0;
        try (PrintWriter w = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(out), "UTF-8")))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled() || written >= limit) break;
                if (f.isExternal()) continue;      // thunks ARE emitted: a skipped thunk sends every caller to the fallback
                scanned++;
                StringBuilder sb = new StringBuilder();
                boolean leaf = true;
                TreeSet<Long> callees = new TreeSet<>();
                sb.append("{\"entry\":").append(f.getEntryPoint().getOffset())
                  .append(",\"name\":\"").append(f.getName().replace("\"", "")).append("\",\"insns\":[");
                boolean first = true;
                for (Instruction in : flowBody(f)) {
                    FlowType ft = in.getFlowType();
                    if (ft.isCall()) {
                        leaf = false;
                        for (Address a : in.getFlows()) callees.add(a.getOffset());
                    }
                    if (ft.isJump() && ft.isComputed()) {
                        boolean resolved = false;
                        for (Reference r : in.getReferencesFrom())
                            if (r.getReferenceType().isFlow()) resolved = true;
                        if (!resolved) leaf = false;
                    }
                    if (!first) sb.append(',');
                    first = false;
                    sb.append("{\"a\":").append(in.getAddress().getOffset())
                      .append(",\"len\":").append(in.getLength())
                      .append(",\"m\":\"").append(in.toString().replace("\\", "\\\\").replace("\"", "'"))
                      .append("\"");
                    // resolved switch targets for BRANCHIND
                    if (ft.isJump() && ft.isComputed()) {
                        sb.append(",\"targets\":[");
                        boolean f2 = true;
                        for (Reference r : in.getReferencesFrom()) {
                            if (!r.getReferenceType().isFlow()) continue;
                            if (!f2) sb.append(',');
                            f2 = false;
                            sb.append(r.getToAddress().getOffset());
                        }
                        sb.append("]");
                    }
                    sb.append(",\"ops\":[");
                    PcodeOp[] ops = in.getPcode();
                    for (int i = 0; i < ops.length; i++) {
                        PcodeOp op = ops[i];
                        if (i > 0) sb.append(',');
                        sb.append("[\"").append(op.getMnemonic()).append("\",").append(vn(op.getOutput())).append(",[");
                        for (int j = 0; j < op.getNumInputs(); j++) {
                            if (j > 0) sb.append(',');
                            sb.append(vn(op.getInput(j)));
                        }
                        sb.append("]]");
                    }
                    sb.append("]}");
                }
                sb.append("],\"callees\":").append(callees.toString().replace(" ", ""))
                  .append(",\"leaf\":").append(leaf).append('}');
                if (mode.equals("leaf") && !leaf) continue;
                w.println(sb);
                written++;
            }
        }

        try (PrintWriter w = new PrintWriter(new File(out.getPath() + ".regs.json"), "UTF-8")) {
            w.print("{");
            boolean first = true;
            for (Register r : currentProgram.getLanguage().getRegisters()) {
                if (r.isProcessorContext()) continue;
                if (!first) w.print(',');
                first = false;
                w.print("\"" + r.getName() + "\":[" + r.getOffset() + "," + r.getMinimumByteSize() + "]");
            }
            w.print("}");
        }
        try (PrintWriter w = new PrintWriter(new File(out.getPath() + ".userops.json"), "UTF-8")) {
            ghidra.program.model.lang.Language lang = currentProgram.getLanguage();
            w.print("[");
            for (int i = 0; i < lang.getNumberOfUserDefinedOpNames(); i++) {
                if (i > 0) w.print(',');
                w.print("\"" + lang.getUserDefinedOpName(i) + "\"");
            }
            w.print("]");
        }
        println(String.format("DumpPcode: scanned %d functions, wrote %d (%s) -> %s", scanned, written, mode, out));
    }
}
