// Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//
// Java, not Python: Ghidra removed the bundled Jython in 11.0, and a .py
// GhidraScript now refuses to run under analyzeHeadless unless the whole tool
// was started with PyGhidra ("Python is not available"). A Java script is
// compiled and run by Ghidra itself on every supported version with no extra
// runtime, so the export path works whether the install is old or new.
//
// @category HeadlessRE

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMP = 200000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = args.length > 1 ? args[1] : null;
        int limit = 256;
        try {
            if (args.length > 2) {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2]), 1024));
            }
        } catch (NumberFormatException e) {
            limit = 256;
        }
        String addressArg = (args.length > 3 && !args[3].isEmpty()) ? args[3] : null;

        List<String> items = new ArrayList<String>();
        boolean hasMore = false;
        StringBuilder extra = new StringBuilder();

        if (mode.equals("functions")) {
            for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                Address entry = fn.getEntryPoint();
                StringBuilder row = new StringBuilder("{");
                row.append("\"name\":").append(jsonStr(fn.getName())).append(",");
                row.append("\"entry\":").append(jsonStr(entry == null ? "" : entry.toString()));
                row.append(",\"body_size\":").append(fn.getBody().getNumAddresses());
                row.append("}");
                items.add(row.toString());
            }
        } else if (mode.equals("symbols")) {
            for (Symbol sym : currentProgram.getSymbolTable().getAllSymbols(true)) {
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                StringBuilder row = new StringBuilder("{");
                row.append("\"name\":").append(jsonStr(sym.getName())).append(",");
                row.append("\"address\":").append(jsonStr(String.valueOf(sym.getAddress()))).append(",");
                row.append("\"type\":").append(jsonStr(String.valueOf(sym.getSymbolType())));
                row.append("}");
                items.add(row.toString());
            }
        } else if (mode.equals("xrefs")) {
            Address addr = addressArg == null ? null : toAddr(addressArg);
            if (addr != null) {
                for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(addr)) {
                    if (items.size() >= limit) {
                        hasMore = true;
                        break;
                    }
                    StringBuilder row = new StringBuilder("{");
                    row.append("\"from\":").append(jsonStr(String.valueOf(ref.getFromAddress()))).append(",");
                    row.append("\"to\":").append(jsonStr(String.valueOf(ref.getToAddress()))).append(",");
                    row.append("\"type\":").append(jsonStr(String.valueOf(ref.getReferenceType())));
                    row.append("}");
                    items.add(row.toString());
                }
            }
        } else if (mode.equals("decompile")) {
            String text = "";
            Address addr = addressArg == null ? null : toAddr(addressArg);
            Function fn = addr == null ? null : currentProgram.getFunctionManager().getFunctionContaining(addr);
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
                extra.append(",\"function\":").append(jsonStr(fn.getName()));
                extra.append(",\"entry\":").append(jsonStr(String.valueOf(fn.getEntryPoint())));
            }
            boolean truncated = text.length() > MAX_DECOMP;
            String clipped = truncated ? text.substring(0, MAX_DECOMP) : text;
            extra.append(",\"decompiled\":").append(jsonStr(clipped));
            extra.append(",\"truncated\":").append(truncated ? "true" : "false");
        } else {
            extra.append(",\"error\":\"unknown mode\"");
        }

        StringBuilder payload = new StringBuilder("{");
        payload.append("\"mode\":").append(jsonStr(mode)).append(",");
        payload.append("\"items\":[").append(join(items)).append("],");
        payload.append("\"count\":").append(items.size()).append(",");
        payload.append("\"has_more\":").append(hasMore ? "true" : "false");
        payload.append(extra);
        payload.append("}");

        if (outPath != null) {
            PrintWriter writer = new PrintWriter(new FileWriter(outPath));
            try {
                writer.write(payload.toString());
            } finally {
                writer.close();
            }
        } else {
            println(payload.toString());
        }
    }

    private static String join(List<String> rows) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(rows.get(i));
        }
        return sb.toString();
    }

    private static String jsonStr(String value) {
        if (value == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
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
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
