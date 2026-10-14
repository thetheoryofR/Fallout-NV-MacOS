// Prints how much of the program is named: total functions, default FUN_ names,
// functions in a class namespace (mostly from RTTI), and RTTI type descriptors found.
//@category BYOG

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class Stats extends GhidraScript {
    @Override
    public void run() throws Exception {
        int total = 0, dflt = 0, inClass = 0, thunks = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            total++;
            if (f.isThunk()) thunks++;
            if (f.getSymbol().getSource() == SourceType.DEFAULT) dflt++;
            if (f.getParentNamespace() instanceof GhidraClass) inClass++;
        }
        int classes = 0, rtti = 0;
        SymbolTable st = currentProgram.getSymbolTable();
        for (Symbol s : st.getDefinedSymbols()) {
            if (s.getSymbolType() == SymbolType.CLASS) classes++;
            if (s.getName().equals("RTTI_Type_Descriptor")) rtti++;
        }
        println(String.format(
            "Stats: functions=%d default_named=%d (%.1f%%) in_class=%d thunks=%d classes=%d rtti_type_descriptors=%d",
            total, dflt, 100.0 * dflt / total, inClass, thunks, classes, rtti));
    }
}
