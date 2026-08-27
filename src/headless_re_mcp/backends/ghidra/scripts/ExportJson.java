// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//
// A native Ghidra Java script rather than a Python one on purpose: Ghidra 11.3
// removed the bundled Jython, so a ``@runtime Jython`` .py post-script fails
// with "Ghidra was not started with PyGhidra" on every current release. Java is
// Ghidra's first-class script language and compiles headlessly on every version
// with no extra runtime, so this keeps ghidra.functions/symbols/xrefs/decompile
// working across the Ghidra versions the client may be pointed at.
//
// Args (from the client): mode, out_path, limit, address. JSON is written to
// out_path as {mode, items, count, has_more} -- decompile adds function, entry,
// decompiled and truncated. JSON is hand-serialised (esc() below) to avoid any
// dependency on a JSON library that may or may not be on Ghidra's classpath.
//
// @category HeadlessRE
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
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ExportJson extends GhidraScript {

    private static final int DECOMPILE_CAP = 200000;

    // Append s to sb as a JSON string literal. Binary-derived names and
    // decompiled C carry quotes, backslashes and control bytes, so every one
    // must be escaped or the client's json.loads rejects the whole export.
    private static void esc(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

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
        // The client passes "" for modes that take no address; treat it as absent.
        String addressArg =
            (args.length > 3 && args[3] != null && !args[3].isEmpty()) ? args[3] : null;

        List<String> items = new ArrayList<>();
        boolean hasMore = false;
        String extra = "";

        if (mode.equals("functions")) {
            FunctionManager fm = currentProgram.getFunctionManager();
            for (Function fn : fm.getFunctions(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                StringBuilder e = new StringBuilder("{");
                e.append("\"name\":");
                esc(e, fn.getName());
                e.append(",\"entry\":");
                esc(e, fn.getEntryPoint().toString());
                e.append(",\"body_size\":").append(fn.getBody().getNumAddresses());
                e.append("}");
                items.add(e.toString());
            }
        } else if (mode.equals("symbols")) {
            SymbolTable st = currentProgram.getSymbolTable();
            for (Symbol sym : st.getAllSymbols(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                StringBuilder e = new StringBuilder("{");
                e.append("\"name\":");
                esc(e, sym.getName());
                e.append(",\"address\":");
                esc(e, sym.getAddress().toString());
                e.append(",\"type\":");
                esc(e, sym.getSymbolType().toString());
                e.append("}");
                items.add(e.toString());
            }
        } else if (mode.equals("xrefs")) {
            if (addressArg != null) {
                Address addr = currentProgram.getAddressFactory().getAddress(addressArg);
                if (addr != null) {
                    ReferenceManager rm = currentProgram.getReferenceManager();
                    for (Reference ref : rm.getReferencesTo(addr)) {
                        if (items.size() >= limit) {
                            hasMore = true;
                            break;
                        }
                        StringBuilder e = new StringBuilder("{");
                        e.append("\"from\":");
                        esc(e, ref.getFromAddress().toString());
                        e.append(",\"to\":");
                        esc(e, ref.getToAddress().toString());
                        e.append(",\"type\":");
                        esc(e, ref.getReferenceType().toString());
                        e.append("}");
                        items.add(e.toString());
                    }
                }
            }
        } else if (mode.equals("decompile")) {
            String text = "";
            String fname = null;
            String fentry = null;
            if (addressArg != null) {
                Address addr = currentProgram.getAddressFactory().getAddress(addressArg);
                Function fn =
                    addr != null ? currentProgram.getFunctionManager().getFunctionContaining(addr)
                                 : null;
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
                    fname = fn.getName();
                    fentry = fn.getEntryPoint().toString();
                }
            }
            boolean truncated = text.length() > DECOMPILE_CAP;
            if (truncated) {
                text = text.substring(0, DECOMPILE_CAP);
            }
            StringBuilder ex = new StringBuilder();
            if (fname != null) {
                ex.append(",\"function\":");
                esc(ex, fname);
            }
            if (fentry != null) {
                ex.append(",\"entry\":");
                esc(ex, fentry);
            }
            ex.append(",\"decompiled\":");
            esc(ex, text);
            ex.append(",\"truncated\":").append(truncated);
            extra = ex.toString();
        } else {
            extra = ",\"error\":\"unknown mode\"";
        }

        StringBuilder out = new StringBuilder();
        out.append("{\"mode\":");
        esc(out, mode);
        out.append(",\"items\":[").append(String.join(",", items)).append("]");
        out.append(",\"count\":").append(items.size());
        out.append(",\"has_more\":").append(hasMore);
        out.append(extra);
        out.append("}");

        if (outPath != null) {
            try (OutputStreamWriter w =
                     new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
                w.write(out.toString());
            }
        } else {
            println(out.toString());
        }
    }
}
