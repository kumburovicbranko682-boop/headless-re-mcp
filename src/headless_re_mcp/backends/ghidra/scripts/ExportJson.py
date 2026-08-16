# Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
# @category HeadlessRE
# @runtime Jython


import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

mode = ARGS[0] if ARGS else "functions"
out_path = ARGS[1] if len(ARGS) > 1 else None
limit = 256
try:
    if len(ARGS) > 2:
        limit = max(1, min(int(ARGS[2]), 1024))
except Exception:
    limit = 256

address_arg = ARGS[3] if len(ARGS) > 3 else None
payload = {"mode": mode, "items": [], "count": 0}
monitor = ConsoleTaskMonitor()
program = currentProgram
fm = program.getFunctionManager()
listing = program.getListing()
refmgr = program.getReferenceManager()
st = program.getSymbolTable()


def _addr(value):
    return program.getAddressFactory().getAddress(value)


if mode == "functions":
    items = []
    has_more = False
    for fn in fm.getFunctions(True):
        if len(items) >= limit:
            # A page that filled used to look like every function. The
            # Python client just forwards this JSON, so a 256-item export
            # with only count made an agent treat the page as the program.
            has_more = True
            break
        entry = fn.getEntryPoint()
        items.append(
            {
                "name": fn.getName(),
                "entry": str(entry),
                "body_size": int(fn.getBody().getNumAddresses()),
            }
        )
    payload["items"] = items
    payload["has_more"] = has_more
elif mode == "symbols":
    items = []
    has_more = False
    for sym in st.getAllSymbols(True):
        if len(items) >= limit:
            # Same silent cut as functions: a 256-item export with only
            # count looked like every recovered symbol.
            has_more = True
            break
        items.append(
            {
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "type": str(sym.getSymbolType()),
            }
        )
    payload["items"] = items
    payload["has_more"] = has_more
elif mode == "xrefs":
    items = []
    has_more = False
    if address_arg:
        addr = _addr(address_arg)
        if addr is not None:
            for ref in refmgr.getReferencesTo(addr):
                if len(items) >= limit:
                    # Same silent cut as functions/symbols: a 256-item
                    # export with only count looked like every reference.
                    has_more = True
                    break
                items.append(
                    {
                        "from": str(ref.getFromAddress()),
                        "to": str(ref.getToAddress()),
                        "type": str(ref.getReferenceType()),
                    }
                )
    payload["items"] = items
    payload["has_more"] = has_more
elif mode == "decompile":
    text = ""
    if address_arg:
        addr = _addr(address_arg)
        fn = fm.getFunctionContaining(addr) if addr is not None else None
        if fn is not None:
            decomp = DecompInterface()
            decomp.openProgram(program)
            try:
                results = decomp.decompileFunction(fn, 30, monitor)
                if results is not None and results.decompileCompleted():
                    text = results.getDecompiledFunction().getC()
            finally:
                decomp.dispose()
            payload["function"] = fn.getName()
            payload["entry"] = str(fn.getEntryPoint())
    payload["decompiled"] = text[:200000]
    # A 200_000-character cut used to look like the whole function.
    # Measured: 250_000 characters came back as 200_000 with no
    # truncated, so an agent treated the fragment as complete.
    payload["truncated"] = len(text) > 200000
    # Empty used to look like a finished decompile. The Python client
    # forwards this JSON, so a missing function or a failed decompile
    # answered with decompiled="" and no error.
    if not text:
        payload["error"] = "decompile produced no code"
else:
    payload["error"] = "unknown mode"

payload["count"] = len(payload.get("items") or [])
if out_path:
    with open(out_path, "w") as handle:
        handle.write(json.dumps(payload))
else:
    print(json.dumps(payload))