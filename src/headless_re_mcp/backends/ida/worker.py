from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from headless_re_mcp.error_boundary import install_global_exception_hooks, record_exception

JsonObject = dict[str, Any]


class WorkerRequestError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


# idalib opens the binary in place, so one sample has one database and a second
# process asking for it is refused with this.
_DATABASE_IN_USE = 4


def _open_database_error(code: int, binary: Path) -> RuntimeError:
    """Say why idalib refused, and whether waiting would have helped.

    Measured with two processes cycling the same fixture, 40 of 50 opens failed
    on code 4 and none did when the same cycles ran one after another. Reported
    as a bare error code and not retryable, it read as a broken sample rather
    than a lock about to be released, and an unattended caller abandoned work it
    only had to repeat -- batch.analyze opens up to eight static sessions at
    once, which is the paths own doing.
    """
    if code == _DATABASE_IN_USE:
        error = RuntimeError(
            f"the IDA database for {binary.name} is already open in another process; "
            "idalib keeps one database per binary, so analyses of the same sample "
            "cannot overlap"
        )
        error.retryable = True  # type: ignore[attr-defined]
        return error
    return RuntimeError(f"idapro.open_database failed with code {code}")


def _emit(payload: JsonObject) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _paging(params: JsonObject) -> tuple[int, int]:
    offset = _integer(params.get("offset", 0), "offset")
    limit = _integer(params.get("limit", 100), "limit")
    if offset < 0:
        raise WorkerRequestError("invalid_argument", "offset must be non-negative", offset=offset)
    if limit < 1 or limit > 1000:
        raise WorkerRequestError(
            "invalid_argument", "limit must be between 1 and 1000", limit=limit
        )
    return offset, limit


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise WorkerRequestError("invalid_argument", f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise WorkerRequestError(
                "invalid_argument", f"{name} must be an integer", value=value
            ) from exc
    raise WorkerRequestError("invalid_argument", f"{name} must be an integer", value=value)


def _overview() -> JsonObject:
    import ida_idaapi
    import ida_kernwin
    import ida_nalt
    import idautils

    functions = list(idautils.Functions())
    strings = list(idautils.Strings())
    image_base = int(ida_nalt.get_imagebase())
    return {
        "kernel_version": ida_kernwin.get_kernel_version(),
        "image_base": image_base,
        "function_count": len(functions),
        "string_count": len(strings),
        "entry_function": int(functions[0]) if functions else image_base,
        "badaddr": int(ida_idaapi.BADADDR),
        "capabilities": sorted(_capabilities()),
    }


def _capabilities() -> frozenset[str]:
    import ida_hexrays

    capabilities = {
        "static.functions",
        "static.strings",
        "static.metadata",
        "static.segments",
        "static.imports",
        "static.exports",
        "static.entrypoints",
        "static.disassemble",
        "static.xrefs_to",
        "static.xrefs_from",
        "static.callers",
        "static.callees",
        "static.basic_blocks",
        "static.cfg",
        "static.globals",
        "static.names",
        "static.types",
        "static.structs",
        "static.enums",
        "static.bytes.read",
        "static.search.bytes",
        "static.search.text",
        "static.search.immediate",
        "static.name.set",
        "static.comment.set",
        "static.type.apply",
        "static.function.create",
        "static.function.delete",
        "static.bytes.patch",
        "static.batch",
    }
    if ida_hexrays.init_hexrays_plugin():
        capabilities.add("static.decompile")
    return frozenset(capabilities)


def _page_items(items: list[JsonObject], offset: int, limit: int) -> JsonObject:
    window = items[offset : offset + limit]
    return {
        "items": window,
        "offset": offset,
        "limit": limit,
        "returned": len(window),
        "total": len(items),
        "has_more": offset + len(window) < len(items),
    }


def _metadata(_params: JsonObject) -> JsonObject:
    import ida_ida
    import ida_nalt
    import idautils

    functions = list(idautils.Functions())
    strings = list(idautils.Strings())
    image_base = int(ida_nalt.get_imagebase())
    input_path = ""
    try:
        input_path = str(ida_nalt.get_input_file_path() or "")
    except Exception:
        input_path = ""
    start_ip = 0
    try:
        start_ip = int(ida_ida.inf_get_start_ip())
    except Exception:
        start_ip = int(functions[0]) if functions else image_base
    bitness = 64
    try:
        bitness = 64 if ida_ida.inf_is_64bit() else 32
    except Exception:
        bitness = 64
    proc = ""
    try:
        proc = str(ida_ida.inf_get_procname() or "")
    except Exception:
        proc = ""
    hashes: JsonObject = {}
    for key, getter in (
        ("md5", getattr(ida_nalt, "retrieve_input_file_md5", None)),
        ("sha256", getattr(ida_nalt, "retrieve_input_file_sha256", None)),
        ("crc32", getattr(ida_nalt, "retrieve_input_file_crc32", None)),
    ):
        if getter is None:
            continue
        try:
            value = getter()
        except Exception:
            continue
        if value is None:
            continue
        if isinstance(value, (bytes, bytearray)):
            hashes[key] = bytes(value).hex()
        else:
            hashes[key] = value if isinstance(value, str) else int(value)
    return {
        "input_path": input_path,
        "image_base": image_base,
        "start_ip": start_ip,
        "bitness": bitness,
        "processor": proc,
        "function_count": len(functions),
        "string_count": len(strings),
        "hashes": hashes,
        "capabilities": sorted(_capabilities()),
        "note": "read-only metadata snapshot from idalib",
    }


def _segments(params: JsonObject) -> JsonObject:
    import ida_segment
    import idautils

    offset, limit = _paging(params)
    items: list[JsonObject] = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg) or ""
        items.append(
            {
                "start": int(seg.start_ea),
                "end": int(seg.end_ea),
                "size": max(0, int(seg.end_ea) - int(seg.start_ea)),
                "name": name,
                "perm": int(seg.perm),
                "bitness": int(seg.bitness) if hasattr(seg, "bitness") else None,
            }
        )
    return _page_items(items, offset, limit)


def _imports(params: JsonObject) -> JsonObject:
    import ida_nalt

    offset, limit = _paging(params)
    items: list[JsonObject] = []
    module_count = int(ida_nalt.get_import_module_qty())
    for module_index in range(module_count):
        module_name = ida_nalt.get_import_module_name(module_index) or ""

        def _collect(
            ea: int,
            name: str,
            ordinal: int,
            *,
            _module: str = module_name,
        ) -> bool:
            items.append(
                {
                    "ea": int(ea),
                    "module": _module,
                    "name": name or None,
                    "ordinal": int(ordinal),
                }
            )
            return True

        ida_nalt.enum_import_names(module_index, _collect)
    return _page_items(items, offset, limit)


def _exports(params: JsonObject) -> JsonObject:
    import idautils

    offset, limit = _paging(params)
    items: list[JsonObject] = []
    for index, ordinal, ea, name in idautils.Entries():
        items.append(
            {
                "index": int(index),
                "ordinal": int(ordinal),
                "ea": int(ea),
                "name": name or None,
            }
        )
    return _page_items(items, offset, limit)


def _entrypoints(params: JsonObject) -> JsonObject:
    import ida_entry
    import ida_ida
    import ida_name

    offset, limit = _paging(params)
    items: list[JsonObject] = []
    try:
        start_ip = int(ida_ida.inf_get_start_ip())
        items.append(
            {
                "ea": start_ip,
                "name": ida_name.get_name(start_ip) or None,
                "kind": "start_ip",
                "ordinal": None,
            }
        )
    except Exception:
        pass
    try:
        qty = int(ida_entry.get_entry_qty())
    except Exception:
        qty = 0
    for index in range(qty):
        try:
            ordinal = int(ida_entry.get_entry_ordinal(index))
            ea = int(ida_entry.get_entry(ordinal))
            name = ida_entry.get_entry_name(ordinal) or ida_name.get_name(ea) or None
        except Exception:
            continue
        items.append(
            {
                "ea": ea,
                "name": name,
                "kind": "entry",
                "ordinal": ordinal,
            }
        )
    # Deduplicate by ea while preserving order.
    seen: set[int] = set()
    unique: list[JsonObject] = []
    for item in items:
        ea = int(item["ea"])
        if ea in seen:
            continue
        seen.add(ea)
        unique.append(item)
    return _page_items(unique, offset, limit)


def _disassemble(params: JsonObject) -> JsonObject:
    import ida_bytes
    import ida_ua
    import idc

    address = _integer(params.get("address"), "address")
    count = _integer(params.get("count", 32), "count")
    if count < 1 or count > 512:
        raise WorkerRequestError(
            "invalid_argument",
            "count must be between 1 and 512",
            count=count,
        )
    max_bytes = _integer(params.get("max_bytes", 4096), "max_bytes")
    if max_bytes < 1 or max_bytes > 65536:
        raise WorkerRequestError(
            "invalid_argument",
            "max_bytes must be between 1 and 65536",
            max_bytes=max_bytes,
        )

    instructions: list[JsonObject] = []
    ea = address
    consumed = 0
    partial = False
    for _ in range(count):
        if consumed >= max_bytes:
            partial = True
            break
        if not ida_bytes.is_loaded(ea):
            partial = True
            break
        insn = ida_ua.insn_t()
        length = int(ida_ua.decode_insn(insn, ea))
        if length <= 0:
            partial = True
            break
        text = idc.generate_disasm_line(ea, 0) or ""
        instructions.append(
            {
                "ea": int(ea),
                "size": length,
                "text": text[:512],
            }
        )
        consumed += length
        ea = int(ea) + length
    return {
        "address": address,
        "count_requested": count,
        "instructions": instructions,
        "returned": len(instructions),
        "next_ea": int(ea),
        "bytes_consumed": consumed,
        "partial": partial,
        "note": "bounded linear disassembly; not a full CFG",
    }


def _xref_type_name(xref_type: int) -> str:
    import ida_xref

    mapping = {
        int(ida_xref.fl_CF): "call_far",
        int(ida_xref.fl_CN): "call_near",
        int(ida_xref.fl_JF): "jump_far",
        int(ida_xref.fl_JN): "jump_near",
        int(ida_xref.fl_F): "ordinary_flow",
        int(ida_xref.dr_O): "data_offset",
        int(ida_xref.dr_W): "data_write",
        int(ida_xref.dr_R): "data_read",
        int(ida_xref.dr_T): "data_text",
        int(ida_xref.dr_I): "data_informational",
    }
    return mapping.get(int(xref_type), f"type_{int(xref_type)}")


def _is_call_xref(xref_type: int) -> bool:
    import ida_xref

    return int(xref_type) in {int(ida_xref.fl_CF), int(ida_xref.fl_CN)}


def _xrefs_to(params: JsonObject) -> JsonObject:
    import idautils

    address = _integer(params.get("address"), "address")
    offset, limit = _paging(params)
    items: list[JsonObject] = []
    for xref in idautils.XrefsTo(address):
        items.append(
            {
                "frm": int(xref.frm),
                "to": int(xref.to),
                "type": int(xref.type),
                "type_name": _xref_type_name(int(xref.type)),
                "iscode": bool(xref.iscode),
            }
        )
    payload = _page_items(items, offset, limit)
    payload["address"] = address
    return payload


def _xrefs_from(params: JsonObject) -> JsonObject:
    import idautils

    address = _integer(params.get("address"), "address")
    offset, limit = _paging(params)
    items: list[JsonObject] = []
    for xref in idautils.XrefsFrom(address):
        items.append(
            {
                "frm": int(xref.frm),
                "to": int(xref.to),
                "type": int(xref.type),
                "type_name": _xref_type_name(int(xref.type)),
                "iscode": bool(xref.iscode),
            }
        )
    payload = _page_items(items, offset, limit)
    payload["address"] = address
    return payload


def _callers(params: JsonObject) -> JsonObject:
    import ida_funcs
    import ida_name
    import idautils

    address = _integer(params.get("address"), "address")
    offset, limit = _paging(params)
    function = ida_funcs.get_func(address)
    target = int(function.start_ea) if function is not None else address
    items: list[JsonObject] = []
    seen: set[int] = set()
    for xref in idautils.XrefsTo(target):
        if not _is_call_xref(int(xref.type)):
            continue
        caller_func = ida_funcs.get_func(int(xref.frm))
        caller_ea = int(caller_func.start_ea) if caller_func is not None else int(xref.frm)
        if caller_ea in seen:
            continue
        seen.add(caller_ea)
        items.append(
            {
                "ea": caller_ea,
                "name": ida_name.get_name(caller_ea) or None,
                "site": int(xref.frm),
                "type_name": _xref_type_name(int(xref.type)),
            }
        )
    payload = _page_items(items, offset, limit)
    payload["address"] = target
    payload["note"] = "call-type xrefs only; not a complete callgraph"
    return payload


def _callees(params: JsonObject) -> JsonObject:
    import ida_bytes
    import ida_funcs
    import ida_name
    import idautils

    address = _integer(params.get("address"), "address")
    offset, limit = _paging(params)
    function = ida_funcs.get_func(address)
    if function is None:
        raise WorkerRequestError(
            "function_not_found",
            f"no function contains address 0x{address:X}",
            address=address,
        )
    start = int(function.start_ea)
    end = int(function.end_ea)
    items: list[JsonObject] = []
    seen: set[int] = set()
    ea = start
    while ea < end:
        for xref in idautils.XrefsFrom(ea):
            if not _is_call_xref(int(xref.type)):
                continue
            target = int(xref.to)
            if target in seen:
                continue
            seen.add(target)
            items.append(
                {
                    "ea": target,
                    "name": ida_name.get_name(target) or None,
                    "site": int(xref.frm),
                    "type_name": _xref_type_name(int(xref.type)),
                }
            )
        insn_len = int(ida_bytes.get_item_size(ea))
        if insn_len <= 0:
            break
        ea = int(ea) + insn_len
    payload = _page_items(items, offset, limit)
    payload["address"] = start
    payload["note"] = "call-type xrefs from function body; not a complete callgraph"
    return payload


def _functions(params: JsonObject) -> JsonObject:
    import ida_funcs
    import ida_name
    import idautils

    offset, limit = _paging(params)
    addresses = list(idautils.Functions())
    items: list[JsonObject] = []
    for ea in addresses[offset : offset + limit]:
        function = ida_funcs.get_func(ea)
        start = int(function.start_ea) if function is not None else int(ea)
        end = int(function.end_ea) if function is not None else start
        name = ida_name.get_name(start) or f"sub_{start:X}"
        items.append(
            {
                "address": start,
                "name": name,
                "end": end,
                "size": max(0, end - start),
                "flags": int(function.flags) if function is not None else 0,
            }
        )
    return {
        "items": items,
        "offset": offset,
        "limit": limit,
        "returned": len(items),
        "total": len(addresses),
    }


def _strings(params: JsonObject) -> JsonObject:
    import idautils

    offset, limit = _paging(params)
    max_length = _integer(params.get("max_length", 4096), "max_length")
    if max_length < 1 or max_length > 65536:
        raise WorkerRequestError(
            "invalid_argument",
            "max_length must be between 1 and 65536",
            max_length=max_length,
        )

    strings = list(idautils.Strings())
    items: list[JsonObject] = []
    for item in strings[offset : offset + limit]:
        value = str(item)
        items.append(
            {
                "address": int(item.ea),
                "length": int(getattr(item, "length", len(value))),
                "type": int(getattr(item, "strtype", 0)),
                "value": value[:max_length],
                "truncated": len(value) > max_length,
            }
        )
    return {
        "items": items,
        "offset": offset,
        "limit": limit,
        "returned": len(items),
        "total": len(strings),
    }


def _decompile(params: JsonObject) -> JsonObject:
    import ida_funcs
    import ida_hexrays
    import idautils

    raw_address = params.get("address")
    if raw_address is None:
        addresses = list(idautils.Functions())
        if not addresses:
            raise WorkerRequestError("function_not_found", "database contains no functions")
        address = int(addresses[0])
    else:
        address = _integer(raw_address, "address")

    function = ida_funcs.get_func(address)
    if function is None:
        raise WorkerRequestError(
            "function_not_found",
            f"no function contains address 0x{address:X}",
            address=address,
        )
    if not ida_hexrays.init_hexrays_plugin():
        raise WorkerRequestError("capability_unavailable", "Hex-Rays decompiler is unavailable")
    cfunc = ida_hexrays.decompile(function.start_ea)
    if cfunc is None:
        raise WorkerRequestError(
            "decompilation_failed",
            f"decompiler returned no result for 0x{int(function.start_ea):X}",
            address=int(function.start_ea),
        )
    text = str(cfunc)
    return {
        "address": int(function.start_ea),
        "end": int(function.end_ea),
        "code": text,
    }


def _require_function(address: int) -> Any:
    import ida_funcs

    function = ida_funcs.get_func(address)
    if function is None:
        raise WorkerRequestError(
            "function_not_found",
            f"no function contains address 0x{address:X}",
            address=address,
        )
    return function


def _basic_blocks(params: JsonObject) -> JsonObject:
    import ida_gdl

    address = _integer(params.get("address"), "address")
    offset, limit = _paging(params)
    function = _require_function(address)
    chart = ida_gdl.FlowChart(function)
    items: list[JsonObject] = []
    for block in chart:
        items.append(
            {
                "id": int(block.id),
                "start": int(block.start_ea),
                "end": int(block.end_ea),
                "size": max(0, int(block.end_ea) - int(block.start_ea)),
                "type": int(block.type),
                "succ_ids": [int(succ.id) for succ in block.succs()],
                "pred_ids": [int(pred.id) for pred in block.preds()],
            }
        )
    payload = _page_items(items, offset, limit)
    payload["address"] = int(function.start_ea)
    payload["function_end"] = int(function.end_ea)
    return payload


def _cfg(params: JsonObject) -> JsonObject:
    import ida_gdl

    address = _integer(params.get("address"), "address")
    function = _require_function(address)
    chart = ida_gdl.FlowChart(function)
    nodes: list[JsonObject] = []
    edges: list[JsonObject] = []
    for block in chart:
        nodes.append(
            {
                "id": int(block.id),
                "start": int(block.start_ea),
                "end": int(block.end_ea),
                "type": int(block.type),
            }
        )
        for succ in block.succs():
            edges.append({"src": int(block.id), "dst": int(succ.id)})
    return {
        "address": int(function.start_ea),
        "function_end": int(function.end_ea),
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "note": "function-local CFG from ida_gdl.FlowChart",
    }


def _names(params: JsonObject) -> JsonObject:
    import idautils

    offset, limit = _paging(params)
    items: list[JsonObject] = []
    for ea, name in idautils.Names():
        items.append({"ea": int(ea), "name": name})
    return _page_items(items, offset, limit)


def _globals(params: JsonObject) -> JsonObject:
    import ida_bytes
    import ida_funcs
    import ida_name
    import idautils

    offset, limit = _paging(params)
    items: list[JsonObject] = []
    for ea, name in idautils.Names():
        if ida_funcs.get_func(ea) is not None:
            continue
        flags = int(ida_bytes.get_flags(ea))
        items.append(
            {
                "ea": int(ea),
                "name": name or ida_name.get_name(ea) or None,
                "is_data": bool(ida_bytes.is_data(flags)),
                "is_code": bool(ida_bytes.is_code(flags)),
                "size": int(ida_bytes.get_item_size(ea)),
            }
        )
    payload = _page_items(items, offset, limit)
    payload["note"] = "named addresses outside functions; not a full data-flow model"
    return payload


def _iter_numbered_types() -> list[JsonObject]:
    import ida_typeinf

    til = ida_typeinf.get_idati()
    items: list[JsonObject] = []
    # IDA 9: get_ordinal_limit; older: get_ordinal_qty
    limit_fn = getattr(ida_typeinf, "get_ordinal_limit", None)
    qty_fn = getattr(ida_typeinf, "get_ordinal_qty", None)
    if limit_fn is not None:
        upper = int(limit_fn(til))
        ordinals = range(1, upper)
    elif qty_fn is not None:
        upper = int(qty_fn(til))
        ordinals = range(1, upper + 1)
    else:
        return items

    for ordinal in ordinals:
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        tinfo = ida_typeinf.tinfo_t()
        ok = False
        getter = getattr(tinfo, "get_numbered_type", None)
        if getter is not None:
            try:
                ok = bool(getter(til, ordinal))
            except Exception:
                ok = False
        kind = "type"
        details: JsonObject = {}
        if ok:
            if tinfo.is_udt():
                kind = "struct" if not tinfo.is_union() else "union"
                try:
                    details["size"] = int(tinfo.get_size())
                except Exception:
                    details["size"] = None
            elif tinfo.is_enum():
                kind = "enum"
                try:
                    details["size"] = int(tinfo.get_size())
                except Exception:
                    details["size"] = None
            elif tinfo.is_func():
                kind = "function"
            elif tinfo.is_ptr():
                kind = "pointer"
            else:
                kind = "typedef"
        items.append(
            {
                "ordinal": int(ordinal),
                "name": name,
                "kind": kind,
                **details,
            }
        )
    return items


def _types(params: JsonObject) -> JsonObject:
    offset, limit = _paging(params)
    items = _iter_numbered_types()
    payload = _page_items(items, offset, limit)
    payload["note"] = "local type library ordinals; best-effort kind classification"
    return payload


def _structs(params: JsonObject) -> JsonObject:
    offset, limit = _paging(params)
    items = [item for item in _iter_numbered_types() if item.get("kind") in {"struct", "union"}]
    return _page_items(items, offset, limit)


def _enums(params: JsonObject) -> JsonObject:
    offset, limit = _paging(params)
    items = [item for item in _iter_numbered_types() if item.get("kind") == "enum"]
    return _page_items(items, offset, limit)


def _bytes_read(params: JsonObject) -> JsonObject:
    import base64

    import ida_bytes

    address = _integer(params.get("address"), "address")
    size = _integer(params.get("size", 64), "size")
    if size < 1 or size > 4096:
        raise WorkerRequestError(
            "invalid_argument",
            "size must be between 1 and 4096",
            size=size,
        )
    if not ida_bytes.is_loaded(address):
        raise WorkerRequestError(
            "invalid_argument",
            f"address 0x{address:X} is not loaded",
            address=address,
        )
    raw = ida_bytes.get_bytes(address, size)
    if raw is None:
        raise WorkerRequestError(
            "read_failed",
            f"failed to read {size} bytes at 0x{address:X}",
            address=address,
            size=size,
        )
    data = bytes(raw)
    return {
        "address": address,
        "size": len(data),
        "hex": data.hex(),
        "base64": base64.b64encode(data).decode("ascii"),
        "truncated": False,
    }


def _normalize_bin_pattern(pattern: str) -> str:
    cleaned = pattern.strip()
    if not cleaned:
        return cleaned
    # Accept "C3", "C3 90", "\\xC3\\x90"
    if "\\x" in cleaned.casefold():
        hex_parts: list[str] = []
        i = 0
        lower = cleaned
        while i < len(lower):
            if lower[i : i + 2].casefold() == "\\x" and i + 4 <= len(lower):
                hex_parts.append(lower[i + 2 : i + 4])
                i += 4
            else:
                i += 1
        if hex_parts:
            return " ".join(hex_parts)
    compact = "".join(ch for ch in cleaned if ch not in " \t")
    if all(ch in "0123456789abcdefABCDEF?" for ch in compact) and len(compact) % 2 == 0:
        return " ".join(compact[i : i + 2] for i in range(0, len(compact), 2))
    return cleaned


def _search_bytes(params: JsonObject) -> JsonObject:
    import ida_bytes
    import ida_ida
    import ida_idaapi

    pattern = params.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        raise WorkerRequestError("invalid_argument", "pattern must be a non-empty string")
    normalized = _normalize_bin_pattern(pattern)
    offset, limit = _paging(params)
    start = params.get("start")
    end = params.get("end")
    start_ea = _integer(start, "start") if start is not None else int(ida_ida.inf_get_min_ea())
    end_ea = _integer(end, "end") if end is not None else int(ida_ida.inf_get_max_ea())
    if end_ea <= start_ea:
        raise WorkerRequestError("invalid_argument", "end must be greater than start")

    matches: list[JsonObject] = []
    ea = start_ea
    compile_vec = getattr(ida_bytes, "compiled_binpat_vec_t", None)
    parse_pat = getattr(ida_bytes, "parse_binpat_str", None)
    bin_search = getattr(ida_bytes, "bin_search", None)
    if compile_vec is None or parse_pat is None or bin_search is None:
        raise WorkerRequestError(
            "capability_unavailable",
            "ida_bytes.bin_search API is unavailable in this IDA build",
        )

    while len(matches) < offset + limit and ea < end_ea:
        patterns = compile_vec()
        parsed = parse_pat(patterns, ea, normalized, 16)
        if parsed is False:
            raise WorkerRequestError(
                "invalid_argument",
                "failed to parse binary pattern",
                pattern=pattern,
                normalized=normalized,
            )
        flags = 0
        for flag_name in ("BIN_SEARCH_FORWARD", "BIN_SEARCH_NOSHOW"):
            flags |= int(getattr(ida_bytes, flag_name, 0) or 0)
        found = bin_search(ea, end_ea, patterns, flags)
        found_ea = int(found[0]) if isinstance(found, tuple) else int(found)
        if found_ea in {ida_idaapi.BADADDR, -1} or found_ea < ea:
            break
        matches.append({"ea": found_ea})
        ea = found_ea + 1
    payload = _page_items(matches, offset, limit)
    payload["pattern"] = pattern
    payload["normalized_pattern"] = normalized
    payload["start"] = start_ea
    payload["end"] = end_ea
    payload["note"] = "bounded bin_search; pattern uses IDA binary string syntax"
    return payload


def _search_text(params: JsonObject) -> JsonObject:
    import ida_ida
    import ida_idaapi
    import ida_search
    import idc

    text = params.get("text")
    if not isinstance(text, str) or text == "":
        raise WorkerRequestError("invalid_argument", "text must be a non-empty string")
    offset, limit = _paging(params)
    start = params.get("start")
    end = params.get("end")
    start_ea = _integer(start, "start") if start is not None else int(ida_ida.inf_get_min_ea())
    end_ea = _integer(end, "end") if end is not None else int(ida_ida.inf_get_max_ea())
    flags = int(ida_search.SEARCH_DOWN)
    matches: list[JsonObject] = []
    ea = start_ea
    while len(matches) < offset + limit:
        found = ida_search.find_text(ea, 0, 0, text, flags)
        if found in {idc.BADADDR, ida_idaapi.BADADDR, -1} or found is None:
            break
        found_ea = int(found)
        if found_ea < ea or found_ea >= end_ea:
            break
        matches.append({"ea": found_ea})
        ea = found_ea + 1
    payload = _page_items(matches, offset, limit)
    payload["text"] = text
    payload["start"] = start_ea
    payload["end"] = end_ea
    return payload


def _search_immediate(params: JsonObject) -> JsonObject:
    import ida_ida
    import ida_idaapi
    import ida_search
    import idc

    value = _integer(params.get("value"), "value")
    offset, limit = _paging(params)
    start = params.get("start")
    end = params.get("end")
    start_ea = _integer(start, "start") if start is not None else int(ida_ida.inf_get_min_ea())
    end_ea = _integer(end, "end") if end is not None else int(ida_ida.inf_get_max_ea())
    flags = int(ida_search.SEARCH_DOWN)
    matches: list[JsonObject] = []
    ea = start_ea
    while len(matches) < offset + limit:
        found = ida_search.find_imm(ea, flags, value)
        # find_imm may return (ea, n) tuple on some builds
        if isinstance(found, tuple):
            found_ea = int(found[0])
            operand = int(found[1]) if len(found) > 1 else None
        else:
            found_ea = int(found)
            operand = None
        if found_ea in {idc.BADADDR, ida_idaapi.BADADDR, -1}:
            break
        if found_ea < ea or found_ea >= end_ea:
            break
        item: JsonObject = {"ea": found_ea, "value": value}
        if operand is not None:
            item["operand"] = operand
        matches.append(item)
        ea = found_ea + 1
    payload = _page_items(matches, offset, limit)
    payload["value"] = value
    payload["start"] = start_ea
    payload["end"] = end_ea
    return payload


def _require_ea_in_database(ea: int) -> None:
    import ida_ida

    min_ea = int(ida_ida.inf_get_min_ea())
    max_ea = int(ida_ida.inf_get_max_ea())
    if not min_ea <= ea < max_ea:
        raise WorkerRequestError(
            "invalid_argument",
            f"address 0x{ea:X} is outside the IDA database range "
            f"[0x{min_ea:X}, 0x{max_ea:X})",
            address=ea,
            min_ea=min_ea,
            max_ea=max_ea,
        )


def _name_set(params: JsonObject) -> JsonObject:
    import ida_name
    import idc

    ea = _integer(params.get("address"), "address")
    _require_ea_in_database(ea)
    name = params.get("name")
    if not isinstance(name, str) or not name.strip():
        raise WorkerRequestError("invalid_argument", "name must be a non-empty string")
    before = idc.get_name(ea) or ""
    ok = bool(ida_name.set_name(ea, name, ida_name.SN_FORCE))
    if not ok:
        raise WorkerRequestError(
            "write_failed",
            f"failed to set name at 0x{ea:X}",
            address=ea,
            name=name,
        )
    after = idc.get_name(ea) or ""
    return {
        "address": ea,
        "name": after,
        "previous_name": before,
        "ok": True,
    }


def _comment_set(params: JsonObject) -> JsonObject:
    import ida_bytes

    ea = _integer(params.get("address"), "address")
    _require_ea_in_database(ea)
    comment = params.get("comment")
    if not isinstance(comment, str):
        raise WorkerRequestError("invalid_argument", "comment must be a string")
    if len(comment) > 4096:
        raise WorkerRequestError(
            "invalid_argument",
            "comment must be at most 4096 characters",
            length=len(comment),
        )
    repeatable = bool(params.get("repeatable", False))
    before = ida_bytes.get_cmt(ea, repeatable) or ""
    ok = bool(ida_bytes.set_cmt(ea, comment, repeatable))
    if not ok:
        raise WorkerRequestError(
            "write_failed",
            f"failed to set comment at 0x{ea:X}",
            address=ea,
        )
    after = ida_bytes.get_cmt(ea, repeatable) or ""
    return {
        "address": ea,
        "comment": after,
        "previous_comment": before,
        "repeatable": repeatable,
        "ok": True,
    }


def _type_apply(params: JsonObject) -> JsonObject:
    import idc

    ea = _integer(params.get("address"), "address")
    _require_ea_in_database(ea)
    type_str = params.get("type")
    if not isinstance(type_str, str) or not type_str.strip():
        raise WorkerRequestError("invalid_argument", "type must be a non-empty string")
    before = idc.get_type(ea) or ""
    ok = bool(idc.SetType(ea, type_str))
    if not ok:
        raise WorkerRequestError(
            "write_failed",
            f"failed to apply type at 0x{ea:X}",
            address=ea,
            type=type_str,
        )
    after = idc.get_type(ea) or ""
    return {
        "address": ea,
        "type": after,
        "previous_type": before,
        "ok": True,
    }


def _function_create(params: JsonObject) -> JsonObject:
    import ida_funcs

    ea = _integer(params.get("address"), "address")
    _require_ea_in_database(ea)
    existing = ida_funcs.get_func(ea)
    if existing is not None and int(existing.start_ea) == ea:
        return {
            "address": ea,
            "created": False,
            "start": int(existing.start_ea),
            "end": int(existing.end_ea),
            "ok": True,
            "note": "function already exists at address",
        }
    ok = bool(ida_funcs.add_func(ea))
    if not ok:
        raise WorkerRequestError(
            "write_failed",
            f"failed to create function at 0x{ea:X}",
            address=ea,
        )
    function = ida_funcs.get_func(ea)
    if function is None:
        raise WorkerRequestError(
            "write_failed",
            f"function create reported success but lookup failed at 0x{ea:X}",
            address=ea,
        )
    return {
        "address": ea,
        "created": True,
        "start": int(function.start_ea),
        "end": int(function.end_ea),
        "ok": True,
    }


def _function_delete(params: JsonObject) -> JsonObject:
    import ida_funcs

    ea = _integer(params.get("address"), "address")
    _require_ea_in_database(ea)
    function = ida_funcs.get_func(ea)
    if function is None:
        raise WorkerRequestError(
            "function_not_found",
            f"no function contains address 0x{ea:X}",
            address=ea,
        )
    start = int(function.start_ea)
    end = int(function.end_ea)
    ok = bool(ida_funcs.del_func(start))
    if not ok:
        raise WorkerRequestError(
            "write_failed",
            f"failed to delete function at 0x{start:X}",
            address=start,
        )
    return {
        "address": start,
        "end": end,
        "deleted": True,
        "ok": True,
    }


def _bytes_patch(params: JsonObject) -> JsonObject:
    import base64

    import ida_bytes

    ea = _integer(params.get("address"), "address")
    _require_ea_in_database(ea)
    raw: bytes | None = None
    if "hex" in params and params.get("hex") is not None:
        hex_value = params.get("hex")
        if not isinstance(hex_value, str):
            raise WorkerRequestError("invalid_argument", "hex must be a string")
        cleaned = "".join(hex_value.split())
        if len(cleaned) % 2 != 0:
            raise WorkerRequestError("invalid_argument", "hex must have even length")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise WorkerRequestError(
                "invalid_argument",
                "hex is not valid hexadecimal",
            ) from exc
    elif "base64" in params and params.get("base64") is not None:
        b64 = params.get("base64")
        if not isinstance(b64, str):
            raise WorkerRequestError("invalid_argument", "base64 must be a string")
        try:
            raw = base64.b64decode(b64, validate=True)
        except Exception as exc:
            raise WorkerRequestError(
                "invalid_argument",
                "base64 is not valid",
            ) from exc
    else:
        raise WorkerRequestError(
            "invalid_argument",
            "bytes.patch requires hex or base64",
        )
    if not raw:
        raise WorkerRequestError("invalid_argument", "patch payload must not be empty")
    if len(raw) > 4096:
        raise WorkerRequestError(
            "invalid_argument",
            "patch payload must be at most 4096 bytes",
            size=len(raw),
        )
    before = ida_bytes.get_bytes(ea, len(raw))
    if before is None:
        raise WorkerRequestError(
            "read_failed",
            f"failed to read {len(raw)} bytes at 0x{ea:X} before patch",
            address=ea,
        )
    before_bytes = bytes(before)
    # IDA 9 idalib may return None from patch_bytes; rely on readback for success.
    ida_bytes.patch_bytes(ea, raw)
    after = ida_bytes.get_bytes(ea, len(raw))
    if after is None or bytes(after) != raw:
        raise WorkerRequestError(
            "write_failed",
            f"failed to patch {len(raw)} bytes at 0x{ea:X}",
            address=ea,
            size=len(raw),
        )
    return {
        "address": ea,
        "size": len(raw),
        "before_hex": before_bytes.hex(),
        "after_hex": raw.hex(),
        "ok": True,
    }


_BATCH_MAX_ITEMS = 32
_BATCH_ALLOWED = frozenset(
    {
        "metadata",
        "segments",
        "imports",
        "exports",
        "entrypoints",
        "disassemble",
        "xrefs_to",
        "xrefs_from",
        "callers",
        "callees",
        "basic_blocks",
        "cfg",
        "globals",
        "names",
        "types",
        "structs",
        "enums",
        "bytes_read",
        "search_bytes",
        "search_text",
        "search_immediate",
        "functions",
        "strings",
        "decompile",
        "name_set",
        "comment_set",
        "type_apply",
        "function_create",
        "function_delete",
        "bytes_patch",
    }
)


def _batch(params: JsonObject) -> JsonObject:
    commands = params.get("commands")
    if not isinstance(commands, list):
        raise WorkerRequestError("invalid_argument", "commands must be a list")
    if len(commands) > _BATCH_MAX_ITEMS:
        raise WorkerRequestError(
            "invalid_argument",
            f"batch is limited to {_BATCH_MAX_ITEMS} commands",
            count=len(commands),
            max_items=_BATCH_MAX_ITEMS,
        )
    results: list[JsonObject] = []
    for index, item in enumerate(commands):
        if not isinstance(item, dict):
            raise WorkerRequestError(
                "invalid_argument",
                f"commands[{index}] must be an object",
                index=index,
            )
        command = item.get("command")
        item_params = item.get("params", {})
        if not isinstance(command, str) or not command:
            raise WorkerRequestError(
                "invalid_argument",
                f"commands[{index}].command must be a non-empty string",
                index=index,
            )
        if command == "batch":
            raise WorkerRequestError(
                "invalid_argument",
                "nested batch commands are not allowed",
                index=index,
            )
        if command not in _BATCH_ALLOWED:
            raise WorkerRequestError(
                "invalid_argument",
                f"commands[{index}] uses unsupported command: {command}",
                index=index,
                command=command,
            )
        if not isinstance(item_params, dict):
            raise WorkerRequestError(
                "invalid_argument",
                f"commands[{index}].params must be an object",
                index=index,
            )
        try:
            data = _dispatch(command, item_params)
            results.append({"index": index, "command": command, "ok": True, "data": data})
        except WorkerRequestError as exc:
            results.append(
                {
                    "index": index,
                    "command": command,
                    "ok": False,
                    "error": {
                        "code": exc.code,
                        "message": str(exc),
                        "details": exc.details,
                    },
                }
            )
    return {
        "count": len(results),
        "max_items": _BATCH_MAX_ITEMS,
        "results": results,
    }


def _dispatch(command: str, params: JsonObject) -> JsonObject:
    handlers: dict[str, Callable[[JsonObject], JsonObject]] = {
        "overview": lambda _: _overview(),
        "metadata": _metadata,
        "segments": _segments,
        "imports": _imports,
        "exports": _exports,
        "entrypoints": _entrypoints,
        "disassemble": _disassemble,
        "xrefs_to": _xrefs_to,
        "xrefs_from": _xrefs_from,
        "callers": _callers,
        "callees": _callees,
        "basic_blocks": _basic_blocks,
        "cfg": _cfg,
        "globals": _globals,
        "names": _names,
        "types": _types,
        "structs": _structs,
        "enums": _enums,
        "bytes_read": _bytes_read,
        "search_bytes": _search_bytes,
        "search_text": _search_text,
        "search_immediate": _search_immediate,
        "functions": _functions,
        "strings": _strings,
        "decompile": _decompile,
        "name_set": _name_set,
        "comment_set": _comment_set,
        "type_apply": _type_apply,
        "function_create": _function_create,
        "function_delete": _function_delete,
        "bytes_patch": _bytes_patch,
        "batch": _batch,
    }
    handler = handlers.get(command)
    if handler is None:
        raise WorkerRequestError("unknown_command", f"unsupported worker command: {command}")
    return handler(params)


def run(binary: Path) -> int:
    install_global_exception_hooks("ida-worker")
    opened = False
    try:
        import idapro

        idapro.enable_console_messages(False)
        import ida_auto

        open_result = idapro.open_database(str(binary), run_auto_analysis=True)
        if open_result:
            raise _open_database_error(int(open_result), binary)
        opened = True
        ida_auto.auto_wait()
        overview = _overview()
        _emit(
            {
                "event": "ready",
                "data": {
                    **overview,
                    "binary": str(binary),
                    "pid": os.getpid(),
                },
            }
        )

        for line in sys.stdin:
            request_id: object = None
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise WorkerRequestError("invalid_request", "request must be a JSON object")
                request_id = request.get("id")
                command = request.get("command")
                params = request.get("params", {})
                if not isinstance(command, str) or not command:
                    raise WorkerRequestError(
                        "invalid_request", "command must be a non-empty string"
                    )
                if not isinstance(params, dict):
                    raise WorkerRequestError("invalid_request", "params must be a JSON object")
                if command == "close":
                    idapro.close_database(False)
                    opened = False
                    _emit({"id": request_id, "ok": True, "data": {"closed": True}})
                    return 0
                _emit({"id": request_id, "ok": True, "data": _dispatch(command, params)})
            except WorkerRequestError as exc:
                _emit(
                    {
                        "id": request_id,
                        "ok": False,
                        "error": {
                            "code": exc.code,
                            "message": str(exc),
                            "details": exc.details,
                            "retryable": False,
                        },
                    }
                )
            except Exception as exc:
                incident = record_exception(exc, context="ida-worker:request")
                _emit(
                    {
                        "id": request_id,
                        "ok": False,
                        "error": {
                            "code": "backend_error",
                            "message": (
                                f"{type(exc).__name__}: {incident['message']} "
                                f"(incident {incident['incident_id']})"
                            ),
                            "details": incident,
                            "retryable": False,
                        },
                    }
                )
        return 0
    except BaseException as exc:
        incident = record_exception(exc, context="ida-worker:fatal")
        _emit(
            {
                "event": "fatal",
                "error": {
                    "code": "worker_start_failed",
                    "message": (
                        f"{type(exc).__name__}: {incident['message']} "
                        f"(incident {incident['incident_id']})"
                    ),
                    "details": incident,
                    # Startup failures are permanent apart from the ones that
                    # are not, and calling those permanent costs a caller the
                    # sample. The exception says which it is when it knows.
                    "retryable": bool(getattr(exc, "retryable", False)),
                },
            }
        )
        return 1
    finally:
        if opened:
            try:
                import idapro

                idapro.close_database(False)
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Persistent IDA idalib JSONL worker")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    return run(args.binary.resolve(strict=True))


if __name__ == "__main__":
    raise SystemExit(main())
