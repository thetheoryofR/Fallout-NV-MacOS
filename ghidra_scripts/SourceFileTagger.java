// Tags functions with the original source file they came from.
//
// Many retail builds keep assert/error strings that embed the developer's source path, e.g.
//   D:\Project\Code\Engine\Magic\MagicSystem.cpp
// Any function that references one of those strings was (almost always) compiled
// from that file. For each such function we add a plate comment naming the file,
// and — only if it still has a default FUN_ name and points at exactly one file —
// rename it <File>_cpp_<addr>. Writes source_files.csv (file, function count).
//
// Run headless: analyzeHeadless <proj_dir> <proj_name> -process -postScript SourceFileTagger.java <outdir>
//@category BYOG

import java.io.*;
import java.util.*;
import java.util.regex.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class SourceFileTagger extends GhidraScript {

    private static final Pattern SRC = Pattern.compile(
        "(?i)[a-z]:\\\\.*\\\\([A-Za-z0-9_]+)\\.(cpp|c|h|inl)$");

    @Override
    public void run() throws Exception {
        String outDir = getScriptArgs().length > 0 ? getScriptArgs()[0] : ".";
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        Map<Function, TreeSet<String>> funcFiles = new HashMap<>();
        Map<String, String> fullPath = new TreeMap<>();

        for (Data d : listing.getDefinedData(true)) {
            if (monitor.isCancelled()) break;
            StringDataInstance s = StringDataInstance.getStringDataInstance(d);
            if (s == StringDataInstance.NULL_INSTANCE) continue;
            String v = s.getStringValue();
            if (v == null) continue;
            Matcher m = SRC.matcher(v.trim());
            if (!m.find()) continue;
            String file = m.group(1) + "." + m.group(2).toLowerCase();
            fullPath.putIfAbsent(file, v.trim());
            for (Reference r : refs.getReferencesTo(d.getAddress())) {
                Function f = fm.getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                funcFiles.computeIfAbsent(f, k -> new TreeSet<>()).add(file);
            }
        }

        Map<String, Integer> counts = new TreeMap<>();
        int renamed = 0;
        for (Map.Entry<Function, TreeSet<String>> e : funcFiles.entrySet()) {
            Function f = e.getKey();
            TreeSet<String> files = e.getValue();
            for (String file : files) counts.merge(file, 1, Integer::sum);

            String note = "Source: " + String.join(", ", files);
            String old = f.getComment();
            if (old == null || !old.contains(note)) {
                f.setComment(old == null ? note : old + "\n" + note);
            }
            if (files.size() == 1 && f.getSymbol().getSource() == SourceType.DEFAULT) {
                String base = files.first().replace('.', '_');
                f.setName(base + "_" + f.getEntryPoint().toString(), SourceType.ANALYSIS);
                renamed++;
            }
        }

        try (PrintWriter w = new PrintWriter(new File(outDir, "source_files.csv"), "UTF-8")) {
            w.println("file,functions,original_path");
            for (Map.Entry<String, Integer> e : counts.entrySet()) {
                w.printf("%s,%d,\"%s\"%n", e.getKey(), e.getValue(), fullPath.get(e.getKey()));
            }
        }
        println(String.format("SourceFileTagger: %d source files, %d tagged functions, %d renamed",
            counts.size(), funcFiles.size(), renamed));
    }
}
