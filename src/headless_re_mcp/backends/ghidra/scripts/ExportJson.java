// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//@category HeadlessRE
//
// Java rather than Python on purpose: Ghidra 11.3 dropped the bundled Jython
// interpreter, so a .py postScript now fails with "Ghidra was not started with
// PyGhidra" on every modern release unless the launcher is swapped and the
// pyghidra package installed. A Java GhidraScript is compiled by Ghidra's own
// script engine on every version, Windows and POSIX alike, with no extra
// runtime -- so the export surface works out of the box wherever analyzeHeadless
// does. The payload shape matches what GhidraClient and the tools catalog
// promise: functions carry name/entry/body_size, symbols name/address/type,
// xrefs from/to/type, and decompile function/entry/decompiled/truncated.

import java.io.FileWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class ExportJson extends GhidraScript {

    // Same 200000-char cap the client documents; a runaway decompilation must
    // not blow past the client's export-byte ceiling and be rejected wholesale.
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
        AddressFactory af = currentProgram.getAddressFactory();

        if ("functions".equals(mode)) {
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                Function fn = it.next();
                JsonObject o = new JsonObject();
                o.addProperty("name", fn.getName());
                o.addProperty("entry", fn.getEntryPoint().toString());
                o.addProperty("body_size", fn.getBody().getNumAddresses());
                items.add(o);
            }
        } else if ("symbols".equals(mode)) {
            SymbolIterator it = st.getAllSymbols(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                Symbol sym = it.next();
                JsonObject o = new JsonObject();
                o.addProperty("name", sym.getName());
                o.addProperty("address", sym.getAddress().toString());
                o.addProperty("type", sym.getSymbolType().toString());
                items.add(o);
            }
        } else if ("xrefs".equals(mode)) {
            if (addressArg != null && !addressArg.isEmpty()) {
                Address addr = af.getAddress(addressArg);
                if (addr != null) {
                    ReferenceIterator refs = refmgr.getReferencesTo(addr);
                    while (refs.hasNext() && !monitor.isCancelled()) {
                        if (items.size() >= limit) {
                            hasMore = true;
                            break;
                        }
                        Reference ref = refs.next();
                        JsonObject o = new JsonObject();
                        o.addProperty("from", ref.getFromAddress().toString());
                        o.addProperty("to", ref.getToAddress().toString());
                        o.addProperty("type", ref.getReferenceType().toString());
                        items.add(o);
                    }
                }
            }
        } else if ("decompile".equals(mode)) {
            String text = "";
            if (addressArg != null && !addressArg.isEmpty()) {
                Address addr = af.getAddress(addressArg);
                Function fn = addr != null ? fm.getFunctionContaining(addr) : null;
                if (fn != null) {
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
            }
            boolean truncated = text.length() > MAX_DECOMPILED;
            payload.addProperty("decompiled", truncated ? text.substring(0, MAX_DECOMPILED) : text);
            payload.addProperty("truncated", truncated);
        } else {
            payload.addProperty("error", "unknown mode");
        }

        payload.add("items", items);
        payload.addProperty("count", items.size());
        payload.addProperty("has_more", hasMore);

        String json = new Gson().toJson(payload);
        if (outPath != null) {
            // Force UTF-8: the client reads this file back as UTF-8, but the
            // no-arg FileWriter writes in the JVM's default charset, so on a
            // non-UTF-8 host locale (or a Windows Ghidra box) a non-ASCII symbol
            // name or a decompiled string with such bytes would be written in a
            // different encoding and fail the client's decode as "export JSON
            // invalid". Pinning UTF-8 here makes writer and reader agree.
            try (Writer writer = new FileWriter(outPath, StandardCharsets.UTF_8)) {
                writer.write(json);
            }
        } else {
            println(json);
        }
    }
}
