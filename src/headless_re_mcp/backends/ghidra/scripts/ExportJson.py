# Export bounded JSON for Headless RE-MCP (analyzeHeadless -postScript).
# @category HeadlessRE
# @runtime Jython


import json

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

try:
    from ghidra.program.model.data import StringDataInstance
except Exception:
    StringDataInstance = None

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
elif mode == "imports":
    items = []
    for fn in fm.getExternalFunctions():
        if len(items) >= limit:
            payload["has_more"] = True
            break
        lib = ""
        addr = ""
        try:
            extloc = fn.getExternalLocation()
            if extloc is not None:
                lib = extloc.getLibraryName() or ""
        except Exception:
            lib = ""
        try:
            entry = fn.getEntryPoint()
            addr = str(entry) if entry is not None else ""
        except Exception:
            addr = ""
        items.append(
            {
                "name": fn.getName(),
                "library": str(lib),
                "address": addr,
            }
        )
    payload["items"] = items
elif mode == "exports":
    items = []
    for addr in st.getExternalEntryPointIterator():
        if len(items) >= limit:
            payload["has_more"] = True
            break
        name = ""
        try:
            sym = st.getPrimarySymbol(addr)
            if sym is not None:
                name = sym.getName()
        except Exception:
            name = ""
        fn = fm.getFunctionAt(addr)
        is_function = fn is not None
        if is_function and not name:
            name = fn.getName()
        items.append(
            {
                "name": name,
                "address": str(addr),
                "is_function": bool(is_function),
            }
        )
    payload["items"] = items
elif mode == "strings":
    items = []
    for data in listing.getDefinedData(True):
        if len(items) >= limit:
            payload["has_more"] = True
            break
        is_str = False
        if StringDataInstance is not None:
            try:
                is_str = StringDataInstance.isString(data)
            except Exception:
                is_str = False
        if not is_str:
            continue
        try:
            value = data.getValue()
            text = "" if value is None else unicode(value)
        except Exception:
            try:
                text = data.getDefaultValueRepresentation()
            except Exception:
                text = ""
        items.append(
            {
                "address": str(data.getAddress()),
                "value": text[:2000],
                "length": int(data.getLength()),
                "data_type": str(data.getDataType().getName()),
                "truncated": len(text) > 2000,
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