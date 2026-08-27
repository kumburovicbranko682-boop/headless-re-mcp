// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//
// Java replaces the former Jython ``ExportJson.py``. Ghidra removed its bundled
// Jython interpreter in 11.4, so a ``@runtime Jython`` script no longer loads --
// analyzeHeadless still reports "Analysis succeeded" but the post-script dies
// with "Ghidra was not started with PyGhidra. Python is not available", writes
// no JSON, and every ghidra.* tool then fails with "export JSON missing after
// postScript". A Java GhidraScript is compiled by Ghidra itself (into the user
// osgi cache, never the read-only package dir) and has been supported on every
// release, so this restores the backend on current Ghidra without pulling in a
// PyGhidra / Jep native dependency. The emitted JSON shape is byte-for-byte the
// same contract the service and tests already consume (mode/items/count/
// has_more, plus function/entry/found/decompiled/truncated for decompile).
//@category HeadlessRE

import java.io.FileWriter;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMP = 200000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = args.length > 1 ? args[1] : null;
        int limit = 256;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2]), 1024));
            } catch (NumberFormatException e) {
                limit = 256;
            }
        }
        String addressArg = args.length > 3 ? args[3] : null;

        JsonObject payload = new JsonObject();
        payload.addProperty("mode", mode);
        JsonArray items = new JsonArray();
        boolean hasMore = false;

        if (mode.equals("functions")) {
            int n = 0;
            for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
                if (n >= limit) {
                    hasMore = true;
                    break;
                }
                JsonObject it = new JsonObject();
                it.addProperty("name", fn.getName());
                it.addProperty("entry", fn.getEntryPoint().toString());
                it.addProperty("body_size", fn.getBody().getNumAddresses());
                items.add(it);
                n++;
            }
        } else if (mode.equals("symbols")) {
            int n = 0;
            for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(true)) {
                if (n >= limit) {
                    hasMore = true;
                    break;
                }
                JsonObject it = new JsonObject();
                it.addProperty("name", sym.getName());
                it.addProperty("address", sym.getAddress().toString());
                it.addProperty("type", sym.getSymbolType().toString());
                items.add(it);
                n++;
            }
        } else if (mode.equals("xrefs")) {
            if (addressArg != null && !addressArg.isEmpty()) {
                Address addr = currentProgram.getAddressFactory().getAddress(addressArg);
                if (addr != null) {
                    int n = 0;
                    for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(addr)) {
                        if (n >= limit) {
                            hasMore = true;
                            break;
                        }
                        JsonObject it = new JsonObject();
                        it.addProperty("from", ref.getFromAddress().toString());
                        it.addProperty("to", ref.getToAddress().toString());
                        it.addProperty("type", ref.getReferenceType().toString());
                        items.add(it);
                        n++;
                    }
                }
            }
        } else if (mode.equals("decompile")) {
            String text = "";
            boolean found = false;
            if (addressArg != null && !addressArg.isEmpty()) {
                Address addr = currentProgram.getAddressFactory().getAddress(addressArg);
                Function fn = addr != null
                    ? currentProgram.getFunctionManager().getFunctionContaining(addr)
                    : null;
                if (fn != null) {
                    found = true;
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(currentProgram);
                    try {
                        DecompileResults results =
                            decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
                        if (results != null && results.decompileCompleted()) {
                            text = results.getDecompiledFunction().getC();
                        }
                    } finally {
                        decomp.dispose();
                    }
                    payload.addProperty("function", fn.getName());
                    payload.addProperty("entry", fn.getEntryPoint().toString());
                }
            }
            // found False means no function contained the address, so decompiled
            // is empty for that reason rather than because the body was empty.
            payload.addProperty("found", found);
            boolean truncated = text.length() > MAX_DECOMP;
            payload.addProperty("decompiled", truncated ? text.substring(0, MAX_DECOMP) : text);
            payload.addProperty("truncated", truncated);
        } else {
            payload.addProperty("error", "unknown mode");
        }

        payload.add("items", items);
        payload.addProperty("count", items.size());
        payload.addProperty("has_more", hasMore);

        if (outPath != null) {
            try (FileWriter handle = new FileWriter(outPath)) {
                handle.write(payload.toString());
            }
        } else {
            println(payload.toString());
        }
    }
}
