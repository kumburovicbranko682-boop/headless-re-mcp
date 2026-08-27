# Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
# @category HeadlessRE
# @runtime Jython


import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Ghidra injects post-script arguments through getScriptArgs(), not a global
# named ARGS -- the latter does not exist, so the previous code raised
# NameError before writing anything and no export was ever produced.
args = getScriptArgs()
mode = args[0] if len(args) > 0 else "functions"
out_path = args[1] if len(args) > 1 else None
limit = 256
try:
    if len(args) > 2:
        limit = max(1, min(int(args[2]), 1024))
except Exception:
    limit = 256

address_arg = args[3] if len(args) > 3 else None
payload = {"mode": mode, "items": [], "count": 0, "has_more": False}
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
    for fn in fm.getFunctions(True):
        if len(items) >= limit:
            payload["has_more"] = True
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
elif mode == "symbols":
    items = []
    for sym in st.getAllSymbols(True):
        if len(items) >= limit:
            payload["has_more"] = True
            break
        items.append(
            {
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "type": str(sym.getSymbolType()),
            }
        )
    payload["items"] = items
elif mode == "xrefs":
    items = []
    if address_arg:
        addr = _addr(address_arg)
        if addr is not None:
            for ref in refmgr.getReferencesTo(addr):
                if len(items) >= limit:
                    payload["has_more"] = True
                    break
                items.append(
                    {
                        "from": str(ref.getFromAddress()),
                        "to": str(ref.getToAddress()),
                        "type": str(ref.getReferenceType()),
                    }
                )
    payload["items"] = items
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
    payload["truncated"] = len(text) > 200000
else:
    payload["error"] = "unknown mode"

payload["count"] = len(payload.get("items") or [])
if out_path:
    with open(out_path, "w") as handle:
        handle.write(json.dumps(payload))
else:
    print(json.dumps(payload))