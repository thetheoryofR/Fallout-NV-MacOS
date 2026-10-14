// Recompilation difficulty census: counts direct vs indirect calls/jumps, resolved
// switch tables, x87 vs SSE instruction use, and instructions in no function.
//@category BYOG

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ControlFlowStats extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        long insns = 0, orphan = 0, dCall = 0, iCall = 0, iCallMem = 0, dJmp = 0, iJmp = 0,
             iJmpResolved = 0, x87 = 0, sse = 0, ret = 0;
        TreeMap<String, Integer> mnem = new TreeMap<>();
        for (Instruction in : listing.getInstructions(true)) {
            if (monitor.isCancelled()) break;
            insns++;
            if (fm.getFunctionContaining(in.getAddress()) == null) orphan++;
            String m = in.getMnemonicString().toUpperCase();
            FlowType ft = in.getFlowType();
            if (ft.isCall()) {
                if (ft.isComputed()) { iCall++; if (in.getOperandType(0) != ghidra.program.model.lang.OperandType.REGISTER) iCallMem++; }
                else dCall++;
            } else if (ft.isJump()) {
                if (ft.isComputed()) {
                    iJmp++;
                    for (Reference r : in.getReferencesFrom())
                        if (r.getReferenceType().isFlow()) { iJmpResolved++; break; }
                } else dJmp++;
            } else if (ft.isTerminal() && m.startsWith("RET")) ret++;
            if (m.startsWith("F") && !m.equals("FEMMS")) x87++;
            if (m.endsWith("SS") || m.endsWith("PS") || m.endsWith("SD") || m.endsWith("PD")
                || m.startsWith("CVT") || m.startsWith("MOVAP") || m.startsWith("MOVUP")) sse++;
            mnem.merge(m, 1, Integer::sum);
        }
        println(String.format("CF: insns=%d orphan=%d direct_calls=%d indirect_calls=%d (mem/vtable %d) "
            + "direct_jumps=%d indirect_jumps=%d resolved=%d rets=%d x87=%d sse=%d distinct_mnemonics=%d",
            insns, orphan, dCall, iCall, iCallMem, dJmp, iJmp, iJmpResolved, ret, x87, sse, mnem.size()));
        StringBuilder sb = new StringBuilder("CF mnemonics:");
        for (Map.Entry<String, Integer> e : mnem.entrySet()) sb.append(' ').append(e.getKey()).append('=').append(e.getValue());
        println(sb.toString());
    }
}
