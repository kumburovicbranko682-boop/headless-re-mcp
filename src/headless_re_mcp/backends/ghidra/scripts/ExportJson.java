// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//
// This is deliberately a Java GhidraScript, not a .py one. From Ghidra 11.2 the
// bundled Jython interpreter is gone and .py scripts are handled by PyGhidra,
// which only runs when Ghidra is launched with PyGhidra enabled -- under a plain
// analyzeHeadless the postScript fails with "Ghidra was not started with
// PyGhidra. Python is not available", so functions/symbols/xrefs/decompile all
// returned no export. A Java GhidraScript is compiled and run by analyzeHeadless
// on every Ghidra build and on every OS with no extra runtime, so the portable
// backend works the same on Linux, macOS and Windows.
//
// JSON is emitted by hand rather than via a bundled library so the script does
// not depend on gson/jackson being present in a given distribution. The shape
// matches what backends/ghidra/client.py parses: an object with mode, items,
// count and has_more, plus the decompile-only decompiled/truncated fields.
// @category HeadlessRE

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMPILED = 200000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = (args.length > 1 && !args[1].isEmpty()) ? args[1] : null;
        int limit = 256;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2]), 1024));
            } catch (NumberFormatException e) {
                limit = 256;
            }
        }
        String addressArg =
            (args.length > 3 && args[3] != null && !args[3].isEmpty()) ? args[3] : null;

        StringBuilder json = new StringBuilder();
        json.append('{');
        appendKey(json, "mode").append(quote(mode));

        if ("functions".equals(mode)) {
            emitFunctions(json, limit);
        } else if ("symbols".equals(mode)) {
            emitSymbols(json, limit);
        } else if ("xrefs".equals(mode)) {
            emitXrefs(json, limit, addressArg);
        } else if ("decompile".equals(mode)) {
            emitDecompile(json, addressArg);
        } else {
            emitEmpty(json);
            json.append(',');
            appendKey(json, "error").append(quote("unknown mode"));
        }

        json.append('}');
        writeOut(outPath, json.toString());
    }

    private void emitFunctions(StringBuilder json, int limit) {
        json.append(',');
        appendKey(json, "items").append('[');
        FunctionManager fm = currentProgram.getFunctionManager();
        int n = 0;
        boolean hasMore = false;
        for (Function fn : fm.getFunctions(true)) {
            if (n >= limit) {
                hasMore = true;
                break;
            }
            if (n > 0) {
                json.append(',');
            }
            json.append('{');
            appendKey(json, "name").append(quote(fn.getName())).append(',');
            appendKey(json, "entry").append(quote(fn.getEntryPoint().toString())).append(',');
            appendKey(json, "body_size").append(fn.getBody().getNumAddresses());
            json.append('}');
            n++;
        }
        json.append(']');
        appendBool(json, "has_more", hasMore);
        appendInt(json, "count", n);
    }

    private void emitSymbols(StringBuilder json, int limit) {
        json.append(',');
        appendKey(json, "items").append('[');
        SymbolTable st = currentProgram.getSymbolTable();
        int n = 0;
        boolean hasMore = false;
        for (Symbol sym : st.getAllSymbols(true)) {
            if (n >= limit) {
                hasMore = true;
                break;
            }
            if (n > 0) {
                json.append(',');
            }
            json.append('{');
            appendKey(json, "name").append(quote(sym.getName())).append(',');
            appendKey(json, "address").append(quote(sym.getAddress().toString())).append(',');
            appendKey(json, "type").append(quote(sym.getSymbolType().toString()));
            json.append('}');
            n++;
        }
        json.append(']');
        appendBool(json, "has_more", hasMore);
        appendInt(json, "count", n);
    }

    private void emitXrefs(StringBuilder json, int limit, String addressArg) {
        json.append(',');
        appendKey(json, "items").append('[');
        int n = 0;
        boolean hasMore = false;
        Address addr = addressArg != null ? toAddr(addressArg) : null;
        if (addr != null) {
            for (Reference ref : getReferencesTo(addr)) {
                if (n >= limit) {
                    hasMore = true;
                    break;
                }
                if (n > 0) {
                    json.append(',');
                }
                json.append('{');
                appendKey(json, "from").append(quote(ref.getFromAddress().toString())).append(',');
                appendKey(json, "to").append(quote(ref.getToAddress().toString())).append(',');
                appendKey(json, "type").append(quote(ref.getReferenceType().toString()));
                json.append('}');
                n++;
            }
        }
        json.append(']');
        appendBool(json, "has_more", hasMore);
        appendInt(json, "count", n);
    }

    private void emitDecompile(StringBuilder json, String addressArg) {
        emitEmpty(json);
        String text = "";
        String function = null;
        String entry = null;
        Address addr = addressArg != null ? toAddr(addressArg) : null;
        Function fn = addr != null ? getFunctionContaining(addr) : null;
        if (fn != null) {
            function = fn.getName();
            entry = fn.getEntryPoint().toString();
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
        }
        boolean truncated = text.length() > MAX_DECOMPILED;
        json.append(',');
        appendKey(json, "decompiled")
            .append(quote(truncated ? text.substring(0, MAX_DECOMPILED) : text));
        appendBool(json, "truncated", truncated);
        if (function != null) {
            json.append(',');
            appendKey(json, "function").append(quote(function));
            json.append(',');
            appendKey(json, "entry").append(quote(entry));
        }
    }

    private void emitEmpty(StringBuilder json) {
        json.append(',');
        appendKey(json, "items").append("[]");
        appendBool(json, "has_more", false);
        appendInt(json, "count", 0);
    }

    private void writeOut(String outPath, String out) throws Exception {
        if (outPath != null) {
            try (Writer w =
                new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
                w.write(out);
            }
        } else {
            println(out);
        }
    }

    private StringBuilder appendKey(StringBuilder sb, String key) {
        return sb.append(quote(key)).append(':');
    }

    private void appendBool(StringBuilder sb, String key, boolean value) {
        sb.append(',');
        appendKey(sb, key).append(value ? "true" : "false");
    }

    private void appendInt(StringBuilder sb, String key, long value) {
        sb.append(',');
        appendKey(sb, key).append(value);
    }

    private static String quote(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder b = new StringBuilder(s.length() + 2);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
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
