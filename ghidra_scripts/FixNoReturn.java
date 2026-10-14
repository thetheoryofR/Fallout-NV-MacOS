// Repairs bogus "no-return" analysis: a function that contains a RET does return. For each such
// function the flag is cleared, and the fall-through after every CALL to it (left undisassembled
// because analysis believed the call never returned) is disassembled and re-joined to the caller.
// Also disassembles the fall-through of ANY call whose callee is not no-return and whose next
// address has no instruction. Run WITHOUT -readOnly, then re-run FixEntries.
//@category BYOG

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FixNoReturn extends GhidraScript {
    private final Map<Function, Boolean> retCache = new HashMap<>();

    private boolean containsRet(Function f) {
        return retCache.computeIfAbsent(f, g -> {
            for (Instruction in : currentProgram.getListing().getInstructions(g.getBody(), true))
                if (in.getFlowType().isTerminal() && in.getMnemonicString().toUpperCase().startsWith("RET")) return true;
            return false;
        });
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        int cleared = 0, disasm = 0, grown = 0;

        for (Function f : fm.getFunctions(true)) {
            if (!f.hasNoReturn()) continue;
            boolean hasRet = false;
            for (Instruction in : listing.getInstructions(f.getBody(), true))
                if (in.getFlowType().isTerminal() && in.getMnemonicString().toUpperCase().startsWith("RET")) { hasRet = true; break; }
            if (hasRet) { f.setNoReturn(false); cleared++; }
        }

        List<Address> todo = new ArrayList<>();
        List<Instruction> calls = new ArrayList<>();
        int restored = 0;
        for (Instruction in : listing.getInstructions(true)) {
            if (!in.getFlowType().isCall()) continue;
            Address next = in.getMaxAddress().next();
            if (next == null || listing.getDefinedDataAt(next) != null) continue;
            // strict: only a DIRECT call whose every target resolves (through thunks) to an internal,
            // non-no-return function that actually contains a RET. Indirect calls and calls into
            // imports (ExitProcess, the C++ throw helper, ...) are left exactly as analysis set them.
            Address[] flows = in.getFlows();
            if (flows.length == 0) continue;
            boolean returns = true;
            for (Address t : flows) {
                Function cf = fm.getFunctionAt(t);
                if (cf != null && cf.isThunk()) cf = cf.getThunkedFunction(true);
                if (cf == null || cf.isExternal() || cf.hasNoReturn() || !containsRet(cf)) { returns = false; break; }
            }
            if (!returns) continue;
            // a call to a returning function must fall through: undo the override analysis left
            if (in.getFallThrough() == null) { in.clearFallThroughOverride(); if (in.getFallThrough() == null) in.setFallThrough(next); restored++; calls.add(in); }
            if (listing.getInstructionAt(next) == null) { todo.add(next); calls.add(in); }
        }
        println("FixNoReturn: restored fall-through on " + restored + " calls");
        for (Address a : todo) {
            if (monitor.isCancelled()) break;
            if (listing.getInstructionAt(a) != null) continue;
            DisassembleCommand cmd = new DisassembleCommand(a, null, true);
            if (cmd.applyTo(currentProgram, monitor) && listing.getInstructionAt(a) != null) disasm++;
        }
        // let callers' bodies absorb the recovered code
        Set<Function> callers = new HashSet<>();
        for (Instruction in : calls) {
            Function f = fm.getFunctionContaining(in.getAddress());
            if (f != null) callers.add(f);
        }
        for (Function f : callers) {
            if (CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor)) grown++;
        }
        println(String.format("FixNoReturn: cleared no-return on %d functions, disassembled %d fall-throughs, re-bodied %d callers",
            cleared, disasm, grown));
    }
}
