# Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
# @category HeadlessRE
# @runtime Jython


import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# getScriptArgs() is the portable GhidraScript accessor: it is populated the
# same way under the Jython provider (analyzeHeadless, Ghidra <= 11.2) and under
# PyGhidra (Ghidra >= 11.3, which dropped Jython). The old ARGS global existed
# only in the Jython provider, so reading it broke this script on modern Ghidra.
ARGS = list(getScriptArgs())

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
    return program.getAddressFactory().getAddress(value)


# total is counted by exhausting the same iterator the page is filled from --
# not read from getFunctionCount()/getNumSymbols()/getReferenceCountTo(), which
# can count a different set (externals, dynamic symbols) than the iterator
# yields and so disagree with count/has_more. Counting past the limit stores no
# extra items, so total is O(all) time but O(limit) memory, and has_more is then
# exactly "there are more than this page" -- the pagination contract every other
# reader here (frida.*, proxy.flows, apk.xrefs) already honours with a total.
if mode == "functions":
    items = []
    total = 0
    for fn in fm.getFunctions(True):
        total += 1
        if len(items) >= limit:
            continue
        entry = fn.getEntryPoint()
        items.append(
            {
                "name": fn.getName(),
                "entry": str(entry),
                "body_size": int(fn.getBody().getNumAddresses()),
            }
        )
    payload["items"] = items
    payload["total"] = total
    payload["has_more"] = total > len(items)
elif mode == "symbols":
    items = []
    total = 0
    for sym in st.getAllSymbols(True):
        total += 1
        if len(items) >= limit:
            continue
        items.append(
            {
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "type": str(sym.getSymbolType()),
            }
        )
    payload["items"] = items
    payload["total"] = total
    payload["has_more"] = total > len(items)
elif mode == "xrefs":
    items = []
    total = 0
    if address_arg:
        addr = _addr(address_arg)
        if addr is not None:
            for ref in refmgr.getReferencesTo(addr):
                total += 1
                if len(items) >= limit:
                    continue
                items.append(
                    {
                        "from": str(ref.getFromAddress()),
                        "to": str(ref.getToAddress()),
                        "type": str(ref.getReferenceType()),
                    }
                )
    payload["items"] = items
    payload["total"] = total
    payload["has_more"] = total > len(items)
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