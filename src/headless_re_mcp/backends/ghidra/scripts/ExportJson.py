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
payload = {"mode": mode, "items": [], "count": 0, "has_more": False}
monitor = ConsoleTaskMonitor()
program = currentProgram
fm = program.getFunctionManager()
listing = program.getListing()
refmgr = program.getReferenceManager()
st = program.getSymbolTable()


def _addr(value):
    # getAddress returns None for an unparseable string and raises for some
    # inputs; a malformed address must not crash the whole export, so both
    # answers collapse to None and the caller reports address_resolved False.
    try:
        return program.getAddressFactory().getAddress(value)
    except Exception:
        return None


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
    resolved = False
    if address_arg:
        addr = _addr(address_arg)
        if addr is not None:
            resolved = True
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
    # A malformed or out-of-range address resolves to nothing, which without
    # this flag reads exactly like a valid address that has no references. Say
    # which one it was so a caller can fix a bad address rather than conclude
    # the code is unreferenced.
    payload["address_resolved"] = resolved
elif mode == "decompile":
    text = ""
    found = False
    completed = False
    error = ""
    resolved = False
    if address_arg:
        addr = _addr(address_arg)
        if addr is not None:
            resolved = True
        fn = fm.getFunctionContaining(addr) if addr is not None else None
        if fn is not None:
            found = True
            decomp = DecompInterface()
            decomp.openProgram(program)
            try:
                results = decomp.decompileFunction(fn, 30, monitor)
                if results is not None and results.decompileCompleted():
                    completed = True
                    df = results.getDecompiledFunction()
                    if df is not None:
                        text = df.getC()
                elif results is not None:
                    try:
                        error = results.getErrorMessage() or ""
                    except Exception:
                        error = ""
            finally:
                decomp.dispose()
            payload["function"] = fn.getName()
            payload["entry"] = str(fn.getEntryPoint())
    # found False means no function contained the address, so decompiled is
    # empty for that reason rather than because the body was empty.
    payload["found"] = found
    # Distinguish that from an address that never resolved at all: a bad or
    # out-of-range string leaves found False too, and without this a caller
    # reads "no function here" for what was really a malformed address.
    payload["address_resolved"] = resolved
    # A found function whose decompiler run did not finish (the 30s per-function
    # limit, or an internal error) also comes back with decompiled empty. Every
    # real function has a body, so found True with completed False is a failed
    # decompile, not an empty result -- say so rather than let the empty string
    # read as the body.
    payload["decompile_completed"] = completed
    if error:
        payload["decompile_error"] = error[:2000]
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