// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
// @category HeadlessRE
//
// A Java GhidraScript on purpose: Ghidra compiles and runs .java scripts
// natively in every version, whereas the Python postScript path changed under
// us -- modern Ghidra (11.3+/12.x) dropped the bundled Jython interpreter, so a
// `@runtime Jython` script now aborts headless with "Python is not available".
// Java has no such runtime dependency, so this one script works on old and new
// installs alike. The emitted JSON shape is identical to the former
// ExportJson.py so the client and its tests are unaffected.

import java.io.FileWriter;
import java.io.IOException;

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
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMPILED = 200000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = args.length > 1 ? args[1] : null;
        int limit = 256;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2]), 1024));
            } catch (NumberFormatException ignored) {
                limit = 256;
            }
        }
        String addressArg = args.length > 3 ? args[3] : null;

        JsonObject payload = new JsonObject();
        payload.addProperty("mode", mode);
        JsonArray items = new JsonArray();
        boolean hasMore = false;

        if ("functions".equals(mode)) {
            FunctionManager fm = currentProgram.getFunctionManager();
            for (Function fn : fm.getFunctions(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                JsonObject entry = new JsonObject();
                entry.addProperty("name", fn.getName());
                entry.addProperty("entry", fn.getEntryPoint().toString());
                entry.addProperty("body_size", fn.getBody().getNumAddresses());
                items.add(entry);
            }
        } else if ("symbols".equals(mode)) {
            SymbolTable st = currentProgram.getSymbolTable();
            for (Symbol sym : st.getAllSymbols(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                JsonObject entry = new JsonObject();
                entry.addProperty("name", sym.getName());
                entry.addProperty("address", sym.getAddress().toString());
                entry.addProperty("type", sym.getSymbolType().toString());
                items.add(entry);
            }
        } else if ("xrefs".equals(mode)) {
            Address addr = toAddress(addressArg);
            if (addr != null) {
                ReferenceManager refmgr = currentProgram.getReferenceManager();
                for (Reference ref : refmgr.getReferencesTo(addr)) {
                    if (items.size() >= limit) {
                        hasMore = true;
                        break;
                    }
                    JsonObject entry = new JsonObject();
                    entry.addProperty("from", ref.getFromAddress().toString());
                    entry.addProperty("to", ref.getToAddress().toString());
                    entry.addProperty("type", ref.getReferenceType().toString());
                    items.add(entry);
                }
            }
        } else if ("decompile".equals(mode)) {
            decompile(payload, addressArg);
        } else {
            payload.addProperty("error", "unknown mode");
        }

        payload.add("items", items);
        payload.addProperty("count", items.size());
        payload.addProperty("has_more", hasMore);

        String json = new Gson().toJson(payload);
        if (outPath != null) {
            try (FileWriter handle = new FileWriter(outPath)) {
                handle.write(json);
            } catch (IOException exc) {
                printerr("ExportJson: failed to write " + outPath + ": " + exc);
                throw exc;
            }
        } else {
            println(json);
        }
    }

    private void decompile(JsonObject payload, String addressArg) {
        String text = "";
        boolean found = false;
        Address addr = toAddress(addressArg);
        Function fn = addr != null ? currentProgram.getFunctionManager().getFunctionContaining(addr) : null;
        if (fn != null) {
            found = true;
            DecompInterface decomp = new DecompInterface();
            try {
                decomp.openProgram(currentProgram);
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
        // found=false means no function contained the address, so `decompiled`
        // is empty for that reason rather than because the body was empty.
        payload.addProperty("found", found);
        payload.addProperty(
            "decompiled", text.length() > MAX_DECOMPILED ? text.substring(0, MAX_DECOMPILED) : text);
        payload.addProperty("truncated", text.length() > MAX_DECOMPILED);
    }

    private Address toAddress(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return currentProgram.getAddressFactory().getAddress(value);
        } catch (Exception exc) {
            return null;
        }
    }
}
