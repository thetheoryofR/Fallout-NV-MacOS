// Resolves switch jump tables that auto-analysis left as unresolved computed jumps:
//   JMP dword ptr [reg*4 + TABLE]
// Table entries are read while they point into the code block near the jump; each entry becomes a
// COMPUTED_JUMP flow reference from the JMP (so flow-based bodies include every case) and is
// disassembled. Run WITHOUT -readOnly; follow with FixEntries/DumpPcode.
//@category BYOG

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

public class ResolveJumpTables extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        ReferenceManager rm = currentProgram.getReferenceManager();
        MemoryBlock text = mem.getBlock(".text");
        int jumps = 0, resolved = 0, targets = 0;
        List<Instruction> todo = new ArrayList<>();
        // every computed jump, including ones analysis resolved only partially (e.g. 1 of 23 cases)
        for (Instruction in : listing.getInstructions(true)) {
            FlowType ft = in.getFlowType();
            if (ft.isJump() && ft.isComputed() && !ft.isCall()) todo.add(in);
        }
        for (Instruction in : todo) {
            jumps++;
            if (!in.getMnemonicString().equalsIgnoreCase("JMP")) continue;
            int t = in.getOperandType(0);
            if ((t & OperandType.DYNAMIC) == 0) continue;           // need a memory operand
            long disp = -1; int scale = 0;
            for (Object o : in.getOpObjects(0)) {
                if (o instanceof Scalar) {
                    long v = ((Scalar) o).getUnsignedValue();
                    if (v == 4) scale = 4; else if (v > 0x400000) disp = v;
                }
            }
            if (disp < 0 || scale != 4) continue;
            Address table = toAddr(disp);
            if (!mem.contains(table)) continue;
            // table size from the bounds check: CMP idx, N ; JA default  ->  N + 1 entries
            int bound = -1;
            Instruction p = in.getPrevious();
            for (int k = 0; k < 4 && p != null && bound < 0; k++, p = p.getPrevious()) {
                if (p.getMnemonicString().equalsIgnoreCase("CMP") && p.getNumOperands() == 2)
                    for (Object o : p.getOpObjects(1)) if (o instanceof Scalar) bound = (int) ((Scalar) o).getUnsignedValue() + 1;
            }
            Set<Address> found = new LinkedHashSet<>();
            Set<Address> have = new HashSet<>();
            for (Reference r : in.getReferencesFrom()) if (r.getReferenceType().isFlow()) have.add(r.getToAddress());
            int limit = bound > 0 && bound <= 4096 ? bound : 1024;
            for (int i = 0; i < limit; i++) {
                Address e = table.add(4L * i);
                if (!mem.contains(e)) break;
                long v = mem.getInt(e) & 0xffffffffL;
                Address a = toAddr(v);
                if (!text.contains(a)) break;
                if (bound < 0 && Math.abs(v - in.getAddress().getOffset()) > 0x40000) break;   // unbounded: cases live near their switch
                if (bound < 0 && listing.getDefinedDataContaining(a) != null) break;
                found.add(a);
            }
            if (found.isEmpty()) continue;
            found.removeAll(have);
            if (found.isEmpty()) continue;
            for (Address a : found) {
                Data d = listing.getDefinedDataContaining(a);
                if (d != null) listing.clearCodeUnits(d.getMinAddress(), d.getMaxAddress(), false);
                if (listing.getInstructionAt(a) == null) new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
                if (listing.getInstructionAt(a) == null) continue;
                rm.addMemoryReference(in.getAddress(), a, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
                targets++;
            }
            resolved++;
        }
        println(String.format("ResolveJumpTables: %d unresolved computed jumps, resolved %d tables, %d case targets", jumps, resolved, targets));
    }
}
