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


def _parse_byte_pattern(text):
    # Return (byte_values, mask_values, error). "??" (or "..") is a wildcard
    # byte: value 0, mask 0. A fixed byte gets mask 0xFF. Whitespace is ignored,
    # so "de ad ?? ef" and "dead??ef" parse the same.
    if not text:
        return [], [], "empty pattern"
    cleaned = "".join(text.split())
    if len(cleaned) % 2 != 0:
        return [], [], "pattern must be whole bytes (even hex length)"
    byte_values = []
    mask_values = []
    i = 0
    while i < len(cleaned):
        pair = cleaned[i : i + 2]
        i += 2
        if pair in ("??", ".."):
            byte_values.append(0)
            mask_values.append(0)
            continue
        try:
            byte_values.append(int(pair, 16))
            mask_values.append(0xFF)
        except Exception:
            return [], [], "invalid hex byte: " + pair
    return byte_values, mask_values, None


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
elif mode == "memory_map":
    items = []
    memory = program.getMemory()
    for block in memory.getBlocks():
        if len(items) >= limit:
            payload["has_more"] = True
            break
        try:
            perms = ""
            perms += "r" if block.isRead() else "-"
            perms += "w" if block.isWrite() else "-"
            perms += "x" if block.isExecute() else "-"
            items.append(
                {
                    "name": block.getName(),
                    "start": str(block.getStart()),
                    "end": str(block.getEnd()),
                    "size": int(block.getSize()),
                    "permissions": perms,
                    "read": bool(block.isRead()),
                    "write": bool(block.isWrite()),
                    "execute": bool(block.isExecute()),
                    "initialized": bool(block.isInitialized()),
                    "overlay": bool(block.isOverlay()),
                }
            )
        except Exception:
            continue
    payload["items"] = items
elif mode == "callgraph":
    callees = []
    callers = []
    found = False
    if address_arg:
        addr = _addr(address_arg)
        fn = fm.getFunctionContaining(addr) if addr is not None else None
        if fn is not None:
            found = True
            payload["function"] = fn.getName()
            payload["entry"] = str(fn.getEntryPoint())
            try:
                for callee in fn.getCalledFunctions(monitor):
                    if len(callees) >= limit:
                        payload["callees_has_more"] = True
                        break
                    callees.append(
                        {
                            "name": callee.getName(),
                            "entry": str(callee.getEntryPoint()),
                            "external": bool(callee.isExternal()),
                        }
                    )
            except Exception:
                pass
            try:
                for caller in fn.getCallingFunctions(monitor):
                    if len(callers) >= limit:
                        payload["callers_has_more"] = True
                        break
                    callers.append(
                        {
                            "name": caller.getName(),
                            "entry": str(caller.getEntryPoint()),
                            "external": bool(caller.isExternal()),
                        }
                    )
            except Exception:
                pass
    payload["found"] = found
    payload["callees"] = callees
    payload["callers"] = callers
    payload["callee_count"] = len(callees)
    payload["caller_count"] = len(callers)
elif mode == "disassemble":
    items = []
    found = False
    if address_arg:
        addr = _addr(address_arg)
        fn = fm.getFunctionContaining(addr) if addr is not None else None
        if fn is not None:
            found = True
            payload["function"] = fn.getName()
            payload["entry"] = str(fn.getEntryPoint())
            for instr in listing.getInstructions(fn.getBody(), True):
                if len(items) >= limit:
                    payload["has_more"] = True
                    break
                try:
                    raw = instr.getBytes()
                    hexbytes = "".join("%02x" % (octet & 0xFF) for octet in raw)
                except Exception:
                    hexbytes = ""
                items.append(
                    {
                        "address": str(instr.getAddress()),
                        "mnemonic": str(instr.getMnemonicString()),
                        "text": str(instr),
                        "bytes": hexbytes,
                        "length": int(instr.getLength()),
                    }
                )
    payload["found"] = found
    payload["items"] = items
elif mode == "function":
    found = False
    if address_arg:
        addr = _addr(address_arg)
        fn = fm.getFunctionContaining(addr) if addr is not None else None
        if fn is not None:
            found = True
            payload["function"] = fn.getName()
            payload["entry"] = str(fn.getEntryPoint())
            try:
                payload["signature"] = str(fn.getPrototypeString(True, False))
            except Exception:
                try:
                    payload["signature"] = str(fn.getSignature().getPrototypeString())
                except Exception:
                    payload["signature"] = ""
            try:
                payload["calling_convention"] = str(fn.getCallingConventionName())
            except Exception:
                payload["calling_convention"] = ""
            try:
                payload["return_type"] = str(fn.getReturnType().getName())
            except Exception:
                payload["return_type"] = ""
            try:
                payload["body_size"] = int(fn.getBody().getNumAddresses())
            except Exception:
                payload["body_size"] = 0
            try:
                payload["stack_frame_size"] = int(fn.getStackFrame().getFrameSize())
            except Exception:
                payload["stack_frame_size"] = 0
            payload["is_thunk"] = bool(fn.isThunk())
            payload["is_external"] = bool(fn.isExternal())
            payload["has_no_return"] = bool(fn.hasNoReturn())
            payload["is_varargs"] = bool(fn.hasVarArgs())
            parameters = []
            try:
                for prm in fn.getParameters():
                    if len(parameters) >= limit:
                        payload["parameters_has_more"] = True
                        break
                    try:
                        storage = str(prm.getVariableStorage())
                    except Exception:
                        storage = ""
                    parameters.append(
                        {
                            "name": str(prm.getName()),
                            "data_type": str(prm.getDataType().getName()),
                            "length": int(prm.getLength()),
                            "storage": storage,
                        }
                    )
            except Exception:
                parameters = []
            locals_out = []
            try:
                for var in fn.getLocalVariables():
                    if len(locals_out) >= limit:
                        payload["locals_has_more"] = True
                        break
                    try:
                        offset = int(var.getStackOffset())
                    except Exception:
                        offset = None
                    locals_out.append(
                        {
                            "name": str(var.getName()),
                            "data_type": str(var.getDataType().getName()),
                            "length": int(var.getLength()),
                            "stack_offset": offset,
                        }
                    )
            except Exception:
                locals_out = []
            payload["parameters"] = parameters
            payload["parameter_count"] = len(parameters)
            payload["local_variables"] = locals_out
            payload["local_count"] = len(locals_out)
    payload["found"] = found
elif mode == "data":
    items = []
    for data in listing.getDefinedData(True):
        if len(items) >= limit:
            payload["has_more"] = True
            break
        try:
            label = ""
            sym = st.getPrimarySymbol(data.getAddress())
            if sym is not None:
                label = sym.getName()
            try:
                rep = data.getDefaultValueRepresentation()
            except Exception:
                rep = ""
            if rep is None:
                rep = ""
            items.append(
                {
                    "address": str(data.getAddress()),
                    "label": label,
                    "data_type": str(data.getDataType().getName()),
                    "value": rep[:2000],
                    "length": int(data.getLength()),
                    "is_pointer": bool(data.isPointer()),
                    "truncated": len(rep) > 2000,
                }
            )
        except Exception:
            continue
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
elif mode == "search_bytes":
    matches = []
    payload["pattern"] = address_arg
    byte_values, mask_values, perr = _parse_byte_pattern(address_arg)
    if perr:
        payload["error"] = perr
    else:
        from jarray import array as _jarray

        signed_bytes = [(v - 256 if v > 127 else v) for v in byte_values]
        signed_masks = [(v - 256 if v > 127 else v) for v in mask_values]
        b_arr = _jarray(signed_bytes, "b")
        m_arr = _jarray(signed_masks, "b")
        memory = program.getMemory()
        start = program.getMinAddress()
        payload["searched"] = True
        while start is not None and len(matches) < limit:
            try:
                hit = memory.findBytes(start, b_arr, m_arr, True, monitor)
            except Exception:
                hit = None
            if hit is None:
                break
            entry = {"address": str(hit)}
            try:
                block = memory.getBlock(hit)
                if block is not None:
                    entry["block"] = block.getName()
            except Exception:
                pass
            try:
                fn = fm.getFunctionContaining(hit)
                if fn is not None:
                    entry["function"] = fn.getName()
                    entry["function_entry"] = str(fn.getEntryPoint())
            except Exception:
                pass
            matches.append(entry)
            try:
                start = hit.add(1)
            except Exception:
                break
        if len(matches) >= limit:
            payload["has_more"] = True
    payload["matches"] = matches
    payload["match_count"] = len(matches)
else:
    payload["error"] = "unknown mode"

payload["count"] = len(payload.get("items") or [])
if out_path:
    with open(out_path, "w") as handle:
        handle.write(json.dumps(payload))
else:
    print(json.dumps(payload))