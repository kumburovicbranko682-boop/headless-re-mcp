// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
// @category HeadlessRE
//
// This is the Java port of the original Jython ExportJson.py. Ghidra 11.4
// dropped the bundled Jython interpreter, so a ``.py`` postScript now aborts
// headless analysis with a JythonStubException unless the user hand-installs
// the Jython extension. A Java GhidraScript is compiled on the fly by
// analyzeHeadless and is supported on every Ghidra release, so the whole
// ghidra.functions/symbols/xrefs/decompile line keeps working across versions.
// The emitted JSON must stay byte-for-byte compatible with what GhidraClient
// (and its tests) expect: mode/items/count/has_more for the list modes, plus
// function/entry/decompiled/truncated for decompile.

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMPILED = 200000;
    // A single defined string is capped so one huge embedded blob (a base64
    // payload, an inlined config) cannot dominate the bounded export; the cut
    // is reported per item via "truncated".
    private static final int MAX_STRING_CHARS = 1024;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = args.length > 1 ? args[1] : null;
        int limit = 256;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2].trim()), 1024));
            } catch (NumberFormatException ex) {
                limit = 256;
            }
        }
        String addressArg = args.length > 3 ? args[3] : null;
        if (addressArg != null && addressArg.isEmpty()) {
            addressArg = null;
        }

        String payload;
        if ("functions".equals(mode)) {
            payload = functions(limit);
        } else if ("imports".equals(mode)) {
            payload = imports(limit);
        } else if ("symbols".equals(mode)) {
            payload = symbols(limit);
        } else if ("strings".equals(mode)) {
            payload = strings(limit);
        } else if ("xrefs".equals(mode)) {
            payload = xrefs(limit, addressArg);
        } else if ("decompile".equals(mode)) {
            payload = decompile(addressArg);
        } else {
            payload = "{\"mode\":" + quote(mode)
                + ",\"items\":[],\"count\":0,\"has_more\":false,"
                + "\"error\":\"unknown mode\"}";
        }

        if (outPath != null && !outPath.isEmpty()) {
            Files.write(Paths.get(outPath), payload.getBytes(StandardCharsets.UTF_8));
        } else {
            println(payload);
        }
    }

    private String functions(int limit) {
        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder items = new StringBuilder("[");
        int count = 0;
        boolean hasMore = false;
        for (Function fn : fm.getFunctions(true)) {
            if (count >= limit) {
                hasMore = true;
                break;
            }
            if (count > 0) {
                items.append(',');
            }
            items.append('{')
                .append("\"name\":").append(quote(fn.getName()))
                .append(",\"entry\":").append(quote(fn.getEntryPoint().toString()))
                .append(",\"body_size\":").append(fn.getBody().getNumAddresses())
                .append('}');
            count++;
        }
        items.append(']');
        return listPayload("functions", items, count, hasMore);
    }

    private String imports(int limit) {
        // External (imported) functions: the library APIs the binary calls, which
        // functions() (defined code) and symbols() (everything) do not single out.
        // Only getExternalFunctions and the ExternalLocation lookup are new here;
        // the iterate/emit shape mirrors functions() exactly. The library lookup
        // is guarded so a null ExternalLocation degrades to an empty name.
        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder items = new StringBuilder("[");
        int count = 0;
        boolean hasMore = false;
        for (Function fn : fm.getExternalFunctions()) {
            if (count >= limit) {
                hasMore = true;
                break;
            }
            if (count > 0) {
                items.append(',');
            }
            String library = "";
            try {
                if (fn.getExternalLocation() != null
                        && fn.getExternalLocation().getLibraryName() != null) {
                    library = fn.getExternalLocation().getLibraryName();
                }
            } catch (Exception ex) {
                library = "";
            }
            items.append('{')
                .append("\"name\":").append(quote(fn.getName()))
                .append(",\"entry\":").append(quote(fn.getEntryPoint().toString()))
                .append(",\"library\":").append(quote(library))
                .append('}');
            count++;
        }
        items.append(']');
        return listPayload("imports", items, count, hasMore);
    }

    private String symbols(int limit) {
        SymbolTable st = currentProgram.getSymbolTable();
        StringBuilder items = new StringBuilder("[");
        int count = 0;
        boolean hasMore = false;
        for (Symbol sym : st.getAllSymbols(true)) {
            if (count >= limit) {
                hasMore = true;
                break;
            }
            if (count > 0) {
                items.append(',');
            }
            items.append('{')
                .append("\"name\":").append(quote(sym.getName()))
                .append(",\"address\":").append(quote(sym.getAddress().toString()))
                .append(",\"type\":").append(quote(sym.getSymbolType().toString()))
                .append('}');
            count++;
        }
        items.append(']');
        return listPayload("symbols", items, count, hasMore);
    }

    private String strings(int limit) {
        // Defined string data Ghidra's analysis laid down: the ASCII/Unicode
        // literals with their address, storage length and data type. symbols()
        // (labels) and functions() (code) never surface these, and a raw byte
        // scan (r2 izz) has no data-type or Ghidra-address context. Only string
        // data is emitted; the iterate/emit shape mirrors symbols() otherwise.
        Listing listing = currentProgram.getListing();
        DataIterator it = listing.getDefinedData(true);
        StringBuilder items = new StringBuilder("[");
        int count = 0;
        boolean hasMore = false;
        while (it.hasNext()) {
            Data d = it.next();
            if (d == null || !d.hasStringValue()) {
                continue;
            }
            if (count >= limit) {
                hasMore = true;
                break;
            }
            String value;
            try {
                Object v = d.getValue();
                value = v != null ? v.toString() : d.getDefaultValueRepresentation();
            } catch (Exception ex) {
                value = "";
            }
            if (value == null) {
                value = "";
            }
            boolean truncated = value.length() > MAX_STRING_CHARS;
            if (truncated) {
                value = value.substring(0, MAX_STRING_CHARS);
            }
            String dataType = "";
            try {
                if (d.getDataType() != null) {
                    dataType = d.getDataType().getName();
                }
            } catch (Exception ex) {
                dataType = "";
            }
            if (count > 0) {
                items.append(',');
            }
            items.append('{')
                .append("\"address\":").append(quote(d.getAddress().toString()))
                .append(",\"value\":").append(quote(value))
                .append(",\"length\":").append(d.getLength())
                .append(",\"data_type\":").append(quote(dataType))
                .append(",\"truncated\":").append(truncated)
                .append('}');
            count++;
        }
        items.append(']');
        return listPayload("strings", items, count, hasMore);
    }

    private String xrefs(int limit, String addressArg) {
        ReferenceManager refmgr = currentProgram.getReferenceManager();
        StringBuilder items = new StringBuilder("[");
        int count = 0;
        boolean hasMore = false;
        Address addr = toAddress(addressArg);
        if (addr != null) {
            for (Reference ref : refmgr.getReferencesTo(addr)) {
                if (count >= limit) {
                    hasMore = true;
                    break;
                }
                if (count > 0) {
                    items.append(',');
                }
                items.append('{')
                    .append("\"from\":").append(quote(ref.getFromAddress().toString()))
                    .append(",\"to\":").append(quote(ref.getToAddress().toString()))
                    .append(",\"type\":").append(quote(ref.getReferenceType().toString()))
                    .append('}');
                count++;
            }
        }
        items.append(']');
        return listPayload("xrefs", items, count, hasMore);
    }

    private String decompile(String addressArg) {
        String text = "";
        String functionName = null;
        String entry = null;
        Address addr = toAddress(addressArg);
        Function fn = addr != null ? currentProgram.getFunctionManager().getFunctionContaining(addr) : null;
        if (fn != null) {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            try {
                DecompileResults results = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
                if (results != null && results.decompileCompleted()) {
                    text = results.getDecompiledFunction().getC();
                }
            } finally {
                decomp.dispose();
            }
            functionName = fn.getName();
            entry = fn.getEntryPoint().toString();
        }
        boolean truncated = text.length() > MAX_DECOMPILED;
        if (truncated) {
            text = text.substring(0, MAX_DECOMPILED);
        }
        StringBuilder out = new StringBuilder();
        out.append("{\"mode\":\"decompile\",\"items\":[],\"count\":0,\"has_more\":false");
        if (functionName != null) {
            out.append(",\"function\":").append(quote(functionName));
            out.append(",\"entry\":").append(quote(entry));
        }
        out.append(",\"decompiled\":").append(quote(text));
        out.append(",\"truncated\":").append(truncated);
        out.append('}');
        return out.toString();
    }

    private Address toAddress(String value) {
        if (value == null) {
            return null;
        }
        try {
            return currentProgram.getAddressFactory().getAddress(value);
        } catch (Exception ex) {
            return null;
        }
    }

    private static String listPayload(String mode, StringBuilder items, int count, boolean hasMore) {
        return "{\"mode\":" + quote(mode)
            + ",\"items\":" + items
            + ",\"count\":" + count
            + ",\"has_more\":" + hasMore
            + "}";
    }

    private static String quote(String value) {
        StringBuilder b = new StringBuilder(value.length() + 2);
        b.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    b.append("\\\"");
                    break;
                case '\\':
                    b.append("\\\\");
                    break;
                case '\n':
                    b.append("\\n");
                    break;
                case '\r':
                    b.append("\\r");
                    break;
                case '\t':
                    b.append("\\t");
                    break;
                case '\b':
                    b.append("\\b");
                    break;
                case '\f':
                    b.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
        return b.toString();
    }
}
