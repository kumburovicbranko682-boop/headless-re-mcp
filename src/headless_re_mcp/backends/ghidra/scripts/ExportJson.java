// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//
// A GhidraScript, not a Jython script: Ghidra 11.3+ removed the bundled Jython,
// so the previous ExportJson.py aborted with a JythonStubException on every
// current release. Java scripts are compiled by Ghidra on any supported
// version and use only long-stable API, so this restores functions / symbols /
// xrefs / decompile without a Jython or PyGhidra extension. The emitted JSON
// schema is identical to the old script's, so GhidraClient and its tool
// descriptions are unchanged.
//
//@category HeadlessRE

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMPILE_CHARS = 200000;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = args.length > 1 ? args[1] : null;
        int limit = 256;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2].trim()), 1024));
            } catch (NumberFormatException e) {
                limit = 256;
            }
        }
        String addressArg = args.length > 3 ? args[3] : null;

        JsonObject payload = new JsonObject();
        payload.addProperty("mode", mode);
        JsonArray items = new JsonArray();
        boolean hasMore = false;

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        ReferenceManager refmgr = currentProgram.getReferenceManager();

        if ("functions".equals(mode)) {
            for (Function fn : fm.getFunctions(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                JsonObject o = new JsonObject();
                o.addProperty("name", fn.getName());
                o.addProperty("entry", fn.getEntryPoint().toString());
                o.addProperty("body_size", fn.getBody().getNumAddresses());
                items.add(o);
            }
        } else if ("symbols".equals(mode)) {
            SymbolIterator sit = st.getAllSymbols(true);
            while (sit.hasNext()) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                Symbol sym = sit.next();
                JsonObject o = new JsonObject();
                o.addProperty("name", sym.getName());
                Address symAddr = sym.getAddress();
                o.addProperty("address", symAddr == null ? "" : symAddr.toString());
                o.addProperty("type", sym.getSymbolType().toString());
                items.add(o);
            }
        } else if ("xrefs".equals(mode)) {
            Address addr = resolve(addressArg);
            if (addr != null) {
                ReferenceIterator rit = refmgr.getReferencesTo(addr);
                while (rit.hasNext()) {
                    if (items.size() >= limit) {
                        hasMore = true;
                        break;
                    }
                    Reference ref = rit.next();
                    JsonObject o = new JsonObject();
                    o.addProperty("from", ref.getFromAddress().toString());
                    o.addProperty("to", ref.getToAddress().toString());
                    o.addProperty("type", ref.getReferenceType().toString());
                    items.add(o);
                }
            }
        } else if ("decompile".equals(mode)) {
            String text = "";
            boolean found = false;
            Address addr = resolve(addressArg);
            Function fn = addr == null ? null : fm.getFunctionContaining(addr);
            if (fn != null) {
                found = true;
                DecompInterface decomp = new DecompInterface();
                decomp.openProgram(currentProgram);
                try {
                    DecompileResults results = decomp.decompileFunction(fn, 30, monitor);
                    if (results != null && results.decompileCompleted()) {
                        text = results.getDecompiledFunction().getC();
                    }
                } finally {
                    decomp.dispose();
                }
                payload.addProperty("function", fn.getName());
                payload.addProperty("entry", fn.getEntryPoint().toString());
            }
            // found False means no function contained the address, so decompiled
            // is empty for that reason rather than because the body was empty.
            payload.addProperty("found", found);
            boolean truncated = text.length() > MAX_DECOMPILE_CHARS;
            payload.addProperty(
                "decompiled", truncated ? text.substring(0, MAX_DECOMPILE_CHARS) : text);
            payload.addProperty("truncated", truncated);
        } else {
            payload.addProperty("error", "unknown mode");
        }

        payload.add("items", items);
        payload.addProperty("count", items.size());
        payload.addProperty("has_more", hasMore);

        String json = new Gson().toJson(payload);
        if (outPath != null) {
            try (Writer w =
                    new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
                w.write(json);
            }
        } else {
            println(json);
        }
    }

    private Address resolve(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return currentProgram.getAddressFactory().getAddress(value);
        } catch (Exception e) {
            return null;
        }
    }
}
