# Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
# @category HeadlessRE
#
# No @runtime tag on purpose: the tag pins one script provider, but Jython Ghidra
# (<= 11.2) and PyGhidra Ghidra (>= 11.3) need different ones, and tagging Jython
# made newer Ghidra route the script to a Jython stub that aborts. Left untagged,
# Ghidra selects the provider by the .py extension -- Jython on old installs,
# PyGhidra on new -- and the same script runs on both. The flat-API globals this
# script uses (getScriptArgs, currentProgram, DecompInterface, ...) are injected
# by both providers, so the body is identical.


import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# analyzeHeadless -postScript arguments arrive via the injected getScriptArgs()
# helper, not a bare ARGS global. Referencing ARGS directly raised
# "NameError: name 'ARGS' is not defined" the moment the script actually ran, so
# every functions/symbols/xrefs/decompile export died before reading a mode.
ARGS = getScriptArgs()

mode = ARGS[0] if len(ARGS) > 0 else "functions"
out_path = ARGS[1] if len(ARGS) > 1 else None
limit = 256
try:
    if len(ARGS) > 2:
        limit = max(1, min(int(ARGS[2]), 1024))
except Exception:
    limit = 256

address_arg = ARGS[3] if len(ARGS) > 3 else None
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
    found = False
    if address_arg:
        addr = _addr(address_arg)
        fn = fm.getFunctionContaining(addr) if addr is not None else None
        if fn is not None:
            found = True
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
    # found False means no function contained the address, so decompiled is
    # empty for that reason rather than because the body was empty.
    payload["found"] = found
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