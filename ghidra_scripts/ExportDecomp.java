// Exports decompiled C, one file per original source file (from SourceFileTagger's
// "Source:" comments). Untagged functions are skipped unless the 2nd arg is "all",
// in which case they go to _untagged/<addr-range>.c in chunks of 2000.
//
// Run headless: analyzeHeadless <proj_dir> <proj_name> -process -noanalysis \
//     -postScript ExportDecomp.java <outdir> [all]
//@category BYOG

import java.io.*;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class ExportDecomp extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "exports");
        boolean all = args.length > 1 && args[1].equals("all");
        outDir.mkdirs();

        DecompInterface dec = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        dec.setOptions(opts);
        dec.toggleCCode(true);
        dec.openProgram(currentProgram);

        Map<String, StringBuilder> byFile = new TreeMap<>();
        int done = 0, failed = 0, untagged = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            String key = sourceOf(f);
            if (key == null) {
                if (!all) continue;
                key = String.format("_untagged/%04d", untagged++ / 2000);
            }
            DecompileResults r = dec.decompileFunction(f, 60, monitor);
            StringBuilder sb = byFile.computeIfAbsent(key, k -> new StringBuilder());
            sb.append("// ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append('\n');
            if (r != null && r.decompileCompleted()) {
                sb.append(r.getDecompiledFunction().getC()).append('\n');
                done++;
            } else {
                sb.append("// decompile failed: ")
                  .append(r == null ? "null" : r.getErrorMessage()).append("\n\n");
                failed++;
            }
            if ((done + failed) % 500 == 0) println("ExportDecomp: " + (done + failed) + " functions");
        }
        dec.dispose();

        for (Map.Entry<String, StringBuilder> e : byFile.entrySet()) {
            File out = new File(outDir, e.getKey() + ".c");
            out.getParentFile().mkdirs();
            try (Writer w = new OutputStreamWriter(new FileOutputStream(out), "UTF-8")) {
                w.write(e.getValue().toString());
            }
        }
        println(String.format("ExportDecomp: %d decompiled, %d failed, %d files -> %s",
            done, failed, byFile.size(), outDir));
    }

    /** First file named in the function's "Source:" comment, without extension. */
    private static String sourceOf(Function f) {
        String c = f.getComment();
        if (c == null) return null;
        for (String line : c.split("\n")) {
            if (line.startsWith("Source: ")) {
                String first = line.substring(8).split(",")[0].trim();
                int dot = first.lastIndexOf('.');
                return dot > 0 ? first.substring(0, dot) : first;
            }
        }
        return null;
    }
}
