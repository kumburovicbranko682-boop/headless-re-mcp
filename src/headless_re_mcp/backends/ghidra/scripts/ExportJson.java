//Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
//
//This script is Java on purpose. Ghidra 11.3 deprecated the bundled Jython and
//Ghidra 12 removed it from the default install (it is now an opt-in extension),
//so a "@runtime Jython" postScript silently stopped running on current Ghidra:
//analysis succeeded, the export JSON was never written, and every
//ghidra.functions/symbols/xrefs/decompile call failed. Java scripts are
//compiled by Ghidra's own in-tree compiler on every supported release, so this
//is the one runtime that works across 11.x and 12.x with no extra components.
//
//Contract (mirrors the retired ExportJson.py exactly):
//  getScriptArgs() = [mode, out_path, limit, address]
//  payload keys    = mode/items/count/has_more (+ per-mode extras)
//@category HeadlessRE

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportJson extends GhidraScript {

    private static final int MAX_DECOMPILED_CHARS = 200000;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "functions";
        String outPath = args.length > 1 ? args[1] : null;
        int limit = 256;
        if (args.length > 2) {
            try {
                limit = Math.max(1, Math.min(Integer.parseInt(args[2].trim()), 1024));
            } catch (NumberFormatException exc) {
                limit = 256;
            }
        }
        String addressArg = args.length > 3 ? args[3] : null;

        List<String> items = new ArrayList<>();
        boolean hasMore = false;
        StringBuilder extras = new StringBuilder();

        if (mode.equals("functions")) {
            FunctionIterator functions =
                    currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function fn = functions.next();
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                items.add("{\"name\":" + quote(fn.getName())
                        + ",\"entry\":" + quote(fn.getEntryPoint().toString())
                        + ",\"body_size\":" + fn.getBody().getNumAddresses() + "}");
            }
        } else if (mode.equals("symbols")) {
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol sym = symbols.next();
                if (items.size() >= limit) {
                    hasMore = true;
                    break;
                }
                items.add("{\"name\":" + quote(sym.getName())
                        + ",\"address\":" + quote(sym.getAddress().toString())
                        + ",\"type\":" + quote(sym.getSymbolType().toString()) + "}");
            }
        } else if (mode.equals("xrefs")) {
            Address addr = resolveAddress(addressArg);
            if (addr != null) {
                ReferenceIterator refs =
                        currentProgram.getReferenceManager().getReferencesTo(addr);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    if (items.size() >= limit) {
                        hasMore = true;
                        break;
                    }
                    items.add("{\"from\":" + quote(ref.getFromAddress().toString())
                            + ",\"to\":" + quote(ref.getToAddress().toString())
                            + ",\"type\":" + quote(ref.getReferenceType().toString())
                            + "}");
                }
            }
        } else if (mode.equals("decompile")) {
            String text = "";
            boolean found = false;
            Address addr = resolveAddress(addressArg);
            Function fn = addr == null
                    ? null
                    : currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (fn != null) {
                found = true;
                DecompInterface decomp = new DecompInterface();
                decomp.openProgram(currentProgram);
                try {
                    DecompileResults results =
                            decomp.decompileFunction(fn, DECOMPILE_TIMEOUT_SECONDS, monitor);
                    if (results != null && results.decompileCompleted()) {
                        String c = results.getDecompiledFunction().getC();
                        text = c == null ? "" : c;
                    }
                } finally {
                    decomp.dispose();
                }
                extras.append(",\"function\":").append(quote(fn.getName()));
                extras.append(",\"entry\":").append(quote(fn.getEntryPoint().toString()));
            }
            // found=false means no function contained the address, so decompiled
            // is empty for that reason rather than because the body was empty.
            boolean truncated = text.length() > MAX_DECOMPILED_CHARS;
            String body = truncated ? text.substring(0, MAX_DECOMPILED_CHARS) : text;
            extras.append(",\"found\":").append(found);
            extras.append(",\"decompiled\":").append(quote(body));
            extras.append(",\"truncated\":").append(truncated);
        } else {
            extras.append(",\"error\":").append(quote("unknown mode"));
        }

        StringBuilder payload = new StringBuilder();
        payload.append("{\"mode\":").append(quote(mode));
        payload.append(",\"items\":[").append(String.join(",", items)).append(']');
        payload.append(",\"count\":").append(items.size());
        payload.append(",\"has_more\":").append(hasMore);
        payload.append(extras);
        payload.append('}');

        if (outPath != null && !outPath.isEmpty()) {
            Files.write(Paths.get(outPath),
                    payload.toString().getBytes(StandardCharsets.UTF_8));
        } else {
            println(payload.toString());
        }
    }

    // Named resolveAddress, not parseAddress/toAddr: GhidraScript already
    // declares those, and a clashing signature makes the in-tree compiler
    // reject the whole script ("cannot override ... in GhidraScript"), which
    // reads downstream only as a missing export file.
    private Address resolveAddress(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        // AddressFactory.getAddress returns null (no throw) on an unparseable
        // string, matching the Jython script's behaviour of an empty result.
        return currentProgram.getAddressFactory().getAddress(value);
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }
}
