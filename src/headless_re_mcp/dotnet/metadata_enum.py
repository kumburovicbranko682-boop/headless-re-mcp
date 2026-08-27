"""Bounded ECMA-335 metadata enumeration (M6.4; no dnlib).

Provides paginated type/method/field/resource/string listings, a small IL
opcode subset disassembler, and weak MemberRef-based xref hints. No dnlib.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from headless_re_mcp.detection import pe as pe_mod
from headless_re_mcp.detection.pe import PeFormatError, scan_pe
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError, inspect_dotnet

JsonObject = dict[str, Any]

DEFAULT_LIMIT: Final[int] = 64
MAX_LIMIT: Final[int] = 256
MAX_IL_BYTES: Final[int] = 4096
MAX_IL_INSNS: Final[int] = 256
CAPABILITY: Final[str] = "dotnet_metadata"

_TBL_TYPEDEF: Final[int] = 0x02
_TBL_FIELD: Final[int] = 0x04
_TBL_METHODDEF: Final[int] = 0x06
_TBL_MEMBERREF: Final[int] = 0x0A
_TBL_MANIFESTRESOURCE: Final[int] = 0x28

# Single-byte opcodes: opcode -> (mnemonic, inline-operand byte count). The
# operand size is what keeps the decoder aligned: an unknown opcode that really
# carries an operand made the old subset table read that operand byte as the
# next instruction, so a plain ``ldc.i4.s 10`` turned into two bogus ops. 0x45
# (switch) is variable-length and handled separately.
_SWITCH_OP: Final[int] = 0x45
_OP1: Final[dict[int, tuple[str, int]]] = {
    0x00: ("nop", 0),
    0x01: ("break", 0),
    0x02: ("ldarg.0", 0),
    0x03: ("ldarg.1", 0),
    0x04: ("ldarg.2", 0),
    0x05: ("ldarg.3", 0),
    0x06: ("ldloc.0", 0),
    0x07: ("ldloc.1", 0),
    0x08: ("ldloc.2", 0),
    0x09: ("ldloc.3", 0),
    0x0A: ("stloc.0", 0),
    0x0B: ("stloc.1", 0),
    0x0C: ("stloc.2", 0),
    0x0D: ("stloc.3", 0),
    0x0E: ("ldarg.s", 1),
    0x0F: ("ldarga.s", 1),
    0x10: ("starg.s", 1),
    0x11: ("ldloc.s", 1),
    0x12: ("ldloca.s", 1),
    0x13: ("stloc.s", 1),
    0x14: ("ldnull", 0),
    0x15: ("ldc.i4.m1", 0),
    0x16: ("ldc.i4.0", 0),
    0x17: ("ldc.i4.1", 0),
    0x18: ("ldc.i4.2", 0),
    0x19: ("ldc.i4.3", 0),
    0x1A: ("ldc.i4.4", 0),
    0x1B: ("ldc.i4.5", 0),
    0x1C: ("ldc.i4.6", 0),
    0x1D: ("ldc.i4.7", 0),
    0x1E: ("ldc.i4.8", 0),
    0x1F: ("ldc.i4.s", 1),
    0x20: ("ldc.i4", 4),
    0x21: ("ldc.i8", 8),
    0x22: ("ldc.r4", 4),
    0x23: ("ldc.r8", 8),
    0x25: ("dup", 0),
    0x26: ("pop", 0),
    0x27: ("jmp", 4),
    0x28: ("call", 4),
    0x29: ("calli", 4),
    0x2A: ("ret", 0),
    0x2B: ("br.s", 1),
    0x2C: ("brfalse.s", 1),
    0x2D: ("brtrue.s", 1),
    0x2E: ("beq.s", 1),
    0x2F: ("bge.s", 1),
    0x30: ("bgt.s", 1),
    0x31: ("ble.s", 1),
    0x32: ("blt.s", 1),
    0x33: ("bne.un.s", 1),
    0x34: ("bge.un.s", 1),
    0x35: ("bgt.un.s", 1),
    0x36: ("ble.un.s", 1),
    0x37: ("blt.un.s", 1),
    0x38: ("br", 4),
    0x39: ("brfalse", 4),
    0x3A: ("brtrue", 4),
    0x3B: ("beq", 4),
    0x3C: ("bge", 4),
    0x3D: ("bgt", 4),
    0x3E: ("ble", 4),
    0x3F: ("blt", 4),
    0x40: ("bne.un", 4),
    0x41: ("bge.un", 4),
    0x42: ("bgt.un", 4),
    0x43: ("ble.un", 4),
    0x44: ("blt.un", 4),
    0x46: ("ldind.i1", 0),
    0x47: ("ldind.u1", 0),
    0x48: ("ldind.i2", 0),
    0x49: ("ldind.u2", 0),
    0x4A: ("ldind.i4", 0),
    0x4B: ("ldind.u4", 0),
    0x4C: ("ldind.i8", 0),
    0x4D: ("ldind.i", 0),
    0x4E: ("ldind.r4", 0),
    0x4F: ("ldind.r8", 0),
    0x50: ("ldind.ref", 0),
    0x51: ("stind.ref", 0),
    0x52: ("stind.i1", 0),
    0x53: ("stind.i2", 0),
    0x54: ("stind.i4", 0),
    0x55: ("stind.i8", 0),
    0x56: ("stind.r4", 0),
    0x57: ("stind.r8", 0),
    0x58: ("add", 0),
    0x59: ("sub", 0),
    0x5A: ("mul", 0),
    0x5B: ("div", 0),
    0x5C: ("div.un", 0),
    0x5D: ("rem", 0),
    0x5E: ("rem.un", 0),
    0x5F: ("and", 0),
    0x60: ("or", 0),
    0x61: ("xor", 0),
    0x62: ("shl", 0),
    0x63: ("shr", 0),
    0x64: ("shr.un", 0),
    0x65: ("neg", 0),
    0x66: ("not", 0),
    0x67: ("conv.i1", 0),
    0x68: ("conv.i2", 0),
    0x69: ("conv.i4", 0),
    0x6A: ("conv.i8", 0),
    0x6B: ("conv.r4", 0),
    0x6C: ("conv.r8", 0),
    0x6D: ("conv.u4", 0),
    0x6E: ("conv.u8", 0),
    0x6F: ("callvirt", 4),
    0x70: ("cpobj", 4),
    0x71: ("ldobj", 4),
    0x72: ("ldstr", 4),
    0x73: ("newobj", 4),
    0x74: ("castclass", 4),
    0x75: ("isinst", 4),
    0x76: ("conv.r.un", 0),
    0x79: ("unbox", 4),
    0x7A: ("throw", 0),
    0x7B: ("ldfld", 4),
    0x7C: ("ldflda", 4),
    0x7D: ("stfld", 4),
    0x7E: ("ldsfld", 4),
    0x7F: ("ldsflda", 4),
    0x80: ("stsfld", 4),
    0x81: ("stobj", 4),
    0x82: ("conv.ovf.i1.un", 0),
    0x83: ("conv.ovf.i2.un", 0),
    0x84: ("conv.ovf.i4.un", 0),
    0x85: ("conv.ovf.i8.un", 0),
    0x86: ("conv.ovf.u1.un", 0),
    0x87: ("conv.ovf.u2.un", 0),
    0x88: ("conv.ovf.u4.un", 0),
    0x89: ("conv.ovf.u8.un", 0),
    0x8A: ("conv.ovf.i.un", 0),
    0x8B: ("conv.ovf.u.un", 0),
    0x8C: ("box", 4),
    0x8D: ("newarr", 4),
    0x8E: ("ldlen", 0),
    0x8F: ("ldelema", 4),
    0x90: ("ldelem.i1", 0),
    0x91: ("ldelem.u1", 0),
    0x92: ("ldelem.i2", 0),
    0x93: ("ldelem.u2", 0),
    0x94: ("ldelem.i4", 0),
    0x95: ("ldelem.u4", 0),
    0x96: ("ldelem.i8", 0),
    0x97: ("ldelem.i", 0),
    0x98: ("ldelem.r4", 0),
    0x99: ("ldelem.r8", 0),
    0x9A: ("ldelem.ref", 0),
    0x9B: ("stelem.i", 0),
    0x9C: ("stelem.i1", 0),
    0x9D: ("stelem.i2", 0),
    0x9E: ("stelem.i4", 0),
    0x9F: ("stelem.i8", 0),
    0xA0: ("stelem.r4", 0),
    0xA1: ("stelem.r8", 0),
    0xA2: ("stelem.ref", 0),
    0xA3: ("ldelem", 4),
    0xA4: ("stelem", 4),
    0xA5: ("unbox.any", 4),
    0xB3: ("conv.ovf.i1", 0),
    0xB4: ("conv.ovf.u1", 0),
    0xB5: ("conv.ovf.i2", 0),
    0xB6: ("conv.ovf.u2", 0),
    0xB7: ("conv.ovf.i4", 0),
    0xB8: ("conv.ovf.u4", 0),
    0xB9: ("conv.ovf.i8", 0),
    0xBA: ("conv.ovf.u8", 0),
    0xC2: ("refanyval", 4),
    0xC3: ("ckfinite", 0),
    0xC6: ("mkrefany", 4),
    0xD0: ("ldtoken", 4),
    0xD1: ("conv.u2", 0),
    0xD2: ("conv.u1", 0),
    0xD3: ("conv.i", 0),
    0xD4: ("conv.ovf.i", 0),
    0xD5: ("conv.ovf.u", 0),
    0xD6: ("add.ovf", 0),
    0xD7: ("add.ovf.un", 0),
    0xD8: ("mul.ovf", 0),
    0xD9: ("mul.ovf.un", 0),
    0xDA: ("sub.ovf", 0),
    0xDB: ("sub.ovf.un", 0),
    0xDC: ("endfinally", 0),
    0xDD: ("leave", 4),
    0xDE: ("leave.s", 1),
    0xDF: ("stind.i", 0),
    0xE0: ("conv.u", 0),
}

# Two-byte opcodes, reached through the 0xFE prefix.
_OP2: Final[dict[int, tuple[str, int]]] = {
    0x00: ("arglist", 0),
    0x01: ("ceq", 0),
    0x02: ("cgt", 0),
    0x03: ("cgt.un", 0),
    0x04: ("clt", 0),
    0x05: ("clt.un", 0),
    0x06: ("ldftn", 4),
    0x07: ("ldvirtftn", 4),
    0x09: ("ldarg", 2),
    0x0A: ("ldarga", 2),
    0x0B: ("starg", 2),
    0x0C: ("ldloc", 2),
    0x0D: ("ldloca", 2),
    0x0E: ("stloc", 2),
    0x0F: ("localloc", 0),
    0x11: ("endfilter", 0),
    0x12: ("unaligned.", 1),
    0x13: ("volatile.", 0),
    0x14: ("tail.", 0),
    0x15: ("initobj", 4),
    0x16: ("constrained.", 4),
    0x17: ("cpblk", 0),
    0x18: ("initblk", 0),
    0x19: ("no.", 1),
    0x1A: ("rethrow", 0),
    0x1C: ("sizeof", 4),
    0x1D: ("refanytype", 0),
    0x1E: ("readonly.", 0),
}

# Operands that ECMA-335 defines as signed: branch displacements (short and
# long), leave targets, and the short/wide integer loads. Reading these
# unsigned would report a backward jump as a huge forward offset.
_SIGNED_OPERANDS: Final[frozenset[str]] = frozenset(
    {
        "ldc.i4.s",
        "ldc.i4",
        "ldc.i8",
        "br.s",
        "brfalse.s",
        "brtrue.s",
        "beq.s",
        "bge.s",
        "bgt.s",
        "ble.s",
        "blt.s",
        "bne.un.s",
        "bge.un.s",
        "bgt.un.s",
        "ble.un.s",
        "blt.un.s",
        "leave.s",
        "br",
        "brfalse",
        "brtrue",
        "beq",
        "bge",
        "bgt",
        "ble",
        "blt",
        "bne.un",
        "bge.un",
        "bgt.un",
        "ble.un",
        "blt.un",
        "leave",
    }
)


@dataclass(frozen=True, slots=True)
class Page:
    kind: str
    items: tuple[JsonObject, ...]
    offset: int
    limit: int
    total: int
    truncated: bool
    capability: str = CAPABILITY
    backend: str = "dotnet_metadata"
    claims_universal_unpack: bool = False
    note: str = ""

    def to_dict(self) -> JsonObject:
        return {
            "kind": self.kind,
            "items": list(self.items),
            "offset": self.offset,
            "limit": self.limit,
            "total": self.total,
            "truncated": self.truncated,
            "capability": self.capability,
            "backend": self.backend,
            "not_ida_idalib": True,
            "claims_universal_unpack": self.claims_universal_unpack,
            "note": self.note,
        }


def _clamp_page(offset: int, limit: int) -> tuple[int, int]:
    if offset < 0:
        raise DotnetInspectError("invalid_argument", "offset must be >= 0")
    if limit < 1:
        raise DotnetInspectError("invalid_argument", "limit must be >= 1")
    return offset, min(limit, MAX_LIMIT)


def enumerate_metadata(
    path: Path | str,
    kind: str,
    *,
    offset: int = 0,
    limit: int = DEFAULT_LIMIT,
    require_verified: bool = True,
) -> Page:
    """Paginated enumeration: types|methods|fields|resources|strings."""
    offset, limit = _clamp_page(offset, limit)
    kind_norm = kind.strip().casefold()
    allowed = {"types", "methods", "fields", "resources", "strings"}
    if kind_norm not in allowed:
        raise DotnetInspectError(
            "invalid_argument",
            f"kind must be one of {sorted(allowed)}",
            details={"kind": kind},
        )
    inspect_dotnet(path, require_verified=require_verified)
    meta = _load_metadata_context(Path(path))
    if kind_norm == "strings":
        items = list(_iter_strings_heap(meta))
        note = "ASCII/#Strings heap entries (not full #US decode)"
    elif kind_norm == "types":
        items = list(_iter_typedefs(meta))
        note = "TypeDef Name/Namespace from #~ + #Strings"
    elif kind_norm == "methods":
        items = list(_iter_methoddefs(meta))
        note = "MethodDef Name + RVA; IL via dotnet.il"
    elif kind_norm == "fields":
        items = list(_iter_fields(meta))
        note = "Field Name from Field table"
    else:
        items = list(_iter_resources(meta))
        note = "ManifestResource Name (+ flags/offset)"
    total = len(items)
    window = items[offset : offset + limit]
    return Page(
        kind=kind_norm,
        items=tuple(window),
        offset=offset,
        limit=limit,
        total=total,
        truncated=offset + len(window) < total,
        note=note,
    )


def disassemble_method_il(
    path: Path | str,
    method_token: int,
    *,
    require_verified: bool = True,
    max_bytes: int = MAX_IL_BYTES,
) -> JsonObject:
    """Bounded IL disassembly for MethodDef token 0x06000xxx."""
    inspect_dotnet(path, require_verified=require_verified)
    if (method_token & 0xFF000000) != 0x06000000:
        raise DotnetInspectError(
            "invalid_argument",
            "method_token must be a MethodDef token (0x0600xxxx)",
            details={"method_token": method_token},
        )
    rid = method_token & 0x00FFFFFF
    if rid == 0:
        raise DotnetInspectError("invalid_argument", "method_token rid must be >= 1")
    meta = _load_metadata_context(Path(path))
    methods = list(_iter_methoddefs(meta))
    if rid > len(methods):
        raise DotnetInspectError(
            "not_found",
            f"MethodDef rid {rid} out of range",
            details={"total_methods": len(methods)},
        )
    method = methods[rid - 1]
    rva = int(method.get("rva") or 0)
    if rva == 0:
        return {
            "method_token": method_token,
            "method": method,
            "instructions": [],
            "partial": False,
            "reason": "abstract_or_runtime_managed_no_rva",
            "capability": CAPABILITY,
            "backend": "dotnet_metadata",
            "not_ida_idalib": True,
            "claims_universal_unpack": False,
        }
    body = _read_method_body(meta, rva, max_bytes=max_bytes)
    instructions, partial = _disassemble_il(body["il"], max_insns=MAX_IL_INSNS)
    calls = [
        insn["operand"]
        for insn in instructions
        if insn.get("mnemonic") in {"call", "callvirt", "newobj"}
        and isinstance(insn.get("operand"), int)
    ]
    return {
        "method_token": method_token,
        "method": method,
        "header": body["header"],
        "il_bytes": body["il_len"],
        "instructions": instructions,
        "call_tokens": calls,
        "partial": partial or body["truncated"],
        "capability": CAPABILITY,
        "backend": "dotnet_metadata",
        "not_ida_idalib": True,
        "claims_universal_unpack": False,
        "note": "opcode subset only; not a full CIL / dnlib disassembler",
    }


def list_memberref_xrefs(
    path: Path | str,
    *,
    offset: int = 0,
    limit: int = DEFAULT_LIMIT,
    require_verified: bool = True,
) -> Page:
    """Weak xref listing from MemberRef table (not a full callgraph)."""
    offset, limit = _clamp_page(offset, limit)
    inspect_dotnet(path, require_verified=require_verified)
    meta = _load_metadata_context(Path(path))
    items = list(_iter_memberrefs(meta))
    total = len(items)
    window = items[offset : offset + limit]
    return Page(
        kind="xrefs",
        items=tuple(window),
        offset=offset,
        limit=limit,
        total=total,
        truncated=offset + len(window) < total,
        note="MemberRef name/class hints only; not complete callgraph",
    )


@dataclass
class _MetaCtx:
    path: Path
    pe_data: bytes
    layout: Any
    meta: bytes
    stream_map: dict[str, tuple[int, int]]
    tables: bytes
    strings: bytes
    heap_sizes: int
    string_index_size: int
    blob_index_size: int
    guid_index_size: int
    row_counts: dict[int, int]
    table_data_offset: int


def _load_metadata_context(path: Path) -> _MetaCtx:
    pe_report = scan_pe(path)
    del pe_report
    data = pe_mod._read_pe_bytes(path)  # noqa: SLF001
    layout = pe_mod._parse_layout(data)  # noqa: SLF001
    cor_rva, cor_size = pe_mod._directory(layout, 14)  # noqa: SLF001
    if cor_rva == 0 or cor_size < 72:
        raise DotnetInspectError("not_dotnet", "missing COM descriptor")
    cor_off = pe_mod._rva_to_offset(layout, cor_rva, size=72)  # noqa: SLF001
    header = pe_mod._slice(data, cor_off, 72)  # noqa: SLF001
    meta_rva = int.from_bytes(header[8:12], "little")
    meta_size = int.from_bytes(header[12:16], "little")
    if not meta_rva or meta_size < 16:
        raise DotnetInspectError("clr_unverified", "metadata directory empty")
    meta_off = pe_mod._rva_to_offset(layout, meta_rva, size=min(meta_size, 0x200000))  # noqa: SLF001
    meta = pe_mod._slice(data, meta_off, min(meta_size, 0x200000))  # noqa: SLF001
    if meta[:4] != b"BSJB":
        raise DotnetInspectError("clr_unverified", "metadata not BSJB")
    version_len = int.from_bytes(meta[12:16], "little")
    version_padded = (version_len + 3) & ~3
    cursor = 16 + version_padded
    if cursor + 4 > len(meta):
        raise DotnetInspectError("clr_unverified", "metadata streams truncated")
    stream_count = int.from_bytes(meta[cursor + 2 : cursor + 4], "little")
    cursor += 4
    stream_map: dict[str, tuple[int, int]] = {}
    for _ in range(stream_count):
        if cursor + 8 > len(meta):
            break
        offset = int.from_bytes(meta[cursor : cursor + 4], "little")
        size = int.from_bytes(meta[cursor + 4 : cursor + 8], "little")
        cursor += 8
        name_end = meta.find(b"\0", cursor)
        if name_end < 0:
            break
        name = meta[cursor:name_end].decode("ascii", errors="replace")
        name_len = name_end - cursor + 1
        cursor += (name_len + 3) & ~3
        stream_map[name] = (offset, size)
    tables_key = "#~" if "#~" in stream_map else ("#-" if "#-" in stream_map else None)
    strings = b""
    if "#Strings" in stream_map:
        s_off, s_size = stream_map["#Strings"]
        strings = meta[s_off : s_off + s_size]
    # Verified BSJB with no tables stream => empty enumeration (still valid CLR shell).
    if tables_key is None:
        return _MetaCtx(
            path=path,
            pe_data=data,
            layout=layout,
            meta=meta,
            stream_map=stream_map,
            tables=b"",
            strings=strings,
            heap_sizes=0,
            string_index_size=2,
            blob_index_size=2,
            guid_index_size=2,
            row_counts={},
            table_data_offset=0,
        )
    t_off, t_size = stream_map[tables_key]
    tables = meta[t_off : t_off + t_size]
    if len(tables) < 24:
        return _MetaCtx(
            path=path,
            pe_data=data,
            layout=layout,
            meta=meta,
            stream_map=stream_map,
            tables=tables,
            strings=strings,
            heap_sizes=0,
            string_index_size=2,
            blob_index_size=2,
            guid_index_size=2,
            row_counts={},
            table_data_offset=0,
        )
    heap_sizes = tables[6]
    string_index_size = 4 if (heap_sizes & 0x01) else 2
    guid_index_size = 4 if (heap_sizes & 0x02) else 2
    blob_index_size = 4 if (heap_sizes & 0x04) else 2
    valid = int.from_bytes(tables[8:16], "little")
    cursor = 24
    row_counts: dict[int, int] = {}
    for bit in range(64):
        if valid & (1 << bit):
            if cursor + 4 > len(tables):
                break
            row_counts[bit] = int.from_bytes(tables[cursor : cursor + 4], "little")
            cursor += 4
    return _MetaCtx(
        path=path,
        pe_data=data,
        layout=layout,
        meta=meta,
        stream_map=stream_map,
        tables=tables,
        strings=strings,
        heap_sizes=heap_sizes,
        string_index_size=string_index_size,
        blob_index_size=blob_index_size,
        guid_index_size=guid_index_size,
        row_counts=row_counts,
        table_data_offset=cursor,
    )


def _string_at(meta: _MetaCtx, index: int) -> str | None:
    if index <= 0 or index >= len(meta.strings):
        return None
    end = meta.strings.find(b"\0", index)
    if end < 0:
        end = len(meta.strings)
    return meta.strings[index:end].decode("utf-8", errors="replace")


def _read_index(buf: bytes, at: int, size: int) -> tuple[int, int]:
    if size == 4:
        return int.from_bytes(buf[at : at + 4], "little"), 4
    return int.from_bytes(buf[at : at + 2], "little"), 2


def _coded_index_size(row_counts: dict[int, int], tables: tuple[int, ...], tag_bits: int) -> int:
    max_rows = max((row_counts.get(t, 0) for t in tables), default=0)
    return 4 if max_rows >= (1 << (16 - tag_bits)) else 2


def _simple_index_size(row_counts: dict[int, int], table: int) -> int:
    return 4 if row_counts.get(table, 0) >= 65536 else 2


def _table_row_size(meta: _MetaCtx, table: int) -> int:
    """ECMA-335 II.22 row sizes for tables we may need to skip/parse."""
    rc = meta.row_counts
    s = meta.string_index_size
    b = meta.blob_index_size
    g = meta.guid_index_size
    type_def_or_ref = _coded_index_size(rc, (0x02, 0x01, 0x1B), 2)
    has_constant = _coded_index_size(rc, (0x04, 0x08, 0x17), 2)
    has_custom_attribute = _coded_index_size(
        rc,
        (
            0x06,
            0x04,
            0x01,
            0x02,
            0x08,
            0x09,
            0x0A,
            0x00,
            0x0E,
            0x17,
            0x14,
            0x11,
            0x1A,
            0x1B,
            0x20,
            0x23,
            0x26,
            0x27,
            0x28,
            0x2A,
            0x2C,
            0x2B,
        ),
        5,
    )
    has_field_marshal = _coded_index_size(rc, (0x04, 0x08), 1)
    has_decl_security = _coded_index_size(rc, (0x02, 0x06, 0x20), 2)
    member_ref_parent = _coded_index_size(rc, (0x02, 0x01, 0x1A, 0x06, 0x1B), 3)
    has_semantics = _coded_index_size(rc, (0x14, 0x17), 1)
    method_def_or_ref = _coded_index_size(rc, (0x06, 0x0A), 1)
    member_forwarded = _coded_index_size(rc, (0x04, 0x06), 1)
    implementation = _coded_index_size(rc, (0x26, 0x23, 0x27), 2)
    custom_attribute_type = _coded_index_size(rc, (0x06, 0x0A), 3)
    resolution_scope = _coded_index_size(rc, (0x00, 0x1A, 0x23, 0x01), 2)
    type_or_method_def = _coded_index_size(rc, (0x02, 0x06), 1)

    sizes: dict[int, int] = {
        0x00: 2 + s + g + g + g,  # Module
        0x01: resolution_scope + s + s,  # TypeRef
        0x02: (
            4
            + s
            + s
            + type_def_or_ref
            + _simple_index_size(rc, 0x04)
            + _simple_index_size(rc, 0x06)
        ),
        0x03: _simple_index_size(rc, 0x04),  # FieldPtr
        0x04: 2 + s + b,  # Field
        0x05: _simple_index_size(rc, 0x06),  # MethodPtr
        0x06: 4 + 2 + 2 + s + b + _simple_index_size(rc, 0x08),  # MethodDef
        0x07: _simple_index_size(rc, 0x08),  # ParamPtr
        0x08: 2 + 2 + s,  # Param
        0x09: _simple_index_size(rc, 0x02) + _simple_index_size(rc, 0x06),
        0x0A: member_ref_parent + s + b,  # MemberRef
        0x0B: 2 + has_constant + b,  # Constant
        0x0C: has_custom_attribute + custom_attribute_type + b,
        0x0D: has_field_marshal + b,  # FieldMarshal
        0x0E: 2 + has_decl_security + b,  # DeclSecurity
        0x0F: 2 + 4,  # ClassLayout placeholder; fixed below
        0x10: 4 + _simple_index_size(rc, 0x04),  # FieldLayout
        0x11: b,  # StandAloneSig
        0x12: _simple_index_size(rc, 0x02) + _simple_index_size(rc, 0x14),
        0x13: _simple_index_size(rc, 0x14),  # EventPtr
        0x14: 2 + s + type_def_or_ref,  # Event
        0x15: _simple_index_size(rc, 0x02) + _simple_index_size(rc, 0x17),
        0x16: _simple_index_size(rc, 0x17),  # PropertyPtr
        0x17: 2 + s + b,  # Property
        0x18: 2 + method_def_or_ref + has_semantics,  # MethodSemantics
        0x19: (
            _simple_index_size(rc, 0x02) + method_def_or_ref + method_def_or_ref
        ),
        0x1A: s,  # ModuleRef
        0x1B: b,  # TypeSpec
        0x1C: 2 + member_forwarded + s + _simple_index_size(rc, 0x1A),
        0x1D: 4 + _simple_index_size(rc, 0x04),  # FieldRVA
        0x20: 4 + 2 + 2 + 2 + 2 + 4 + b + s + s,  # Assembly
        0x21: 4,  # AssemblyProcessor
        0x22: 12,  # AssemblyOS
        0x23: 4 + 2 + 2 + 2 + 2 + 4 + b + s + s,  # AssemblyRef
        0x24: 4 + _simple_index_size(rc, 0x23),  # AssemblyRefProcessor
        0x25: 12 + _simple_index_size(rc, 0x23),  # AssemblyRefOS
        0x26: 4 + s + implementation,  # File
        0x27: 0,  # ExportedType; fixed below
        0x28: 4 + 4 + s + implementation,  # ManifestResource
        0x29: _simple_index_size(rc, 0x02) + implementation,  # NestedClass
        0x2A: 0,  # GenericParam; fixed below
        0x2B: _simple_index_size(rc, 0x2A) + type_def_or_ref,
        0x2C: method_def_or_ref + b,  # MethodSpec
    }
    # Fix ClassLayout: PackingSize(2)+ClassSize(4)+Parent TypeDef
    sizes[0x0F] = 2 + 4 + _simple_index_size(rc, 0x02)
    # AssemblyProcessor
    sizes[0x21] = 4
    # ExportedType: Flags(4)+TypeDefId(4)+TypeName(str)+TypeNamespace(str)+Implementation
    sizes[0x27] = 4 + 4 + s + s + implementation
    # GenericParam: Number(2)+Flags(2)+Owner+Name
    sizes[0x2A] = 2 + 2 + type_or_method_def + s

    if table not in sizes:
        raise DotnetInspectError(
            "unsupported_metadata",
            f"cannot size metadata table {table:#x}; enumeration aborted",
            details={"table": table},
        )
    return sizes[table]


def _table_start(meta: _MetaCtx, table: int) -> int:
    offset = meta.table_data_offset
    for bit in range(table):
        rows = meta.row_counts.get(bit)
        if not rows:
            continue
        offset += _table_row_size(meta, bit) * rows
    return offset


def _iter_table_rows(meta: _MetaCtx, table: int) -> Iterable[tuple[int, int]]:
    rows = meta.row_counts.get(table)
    if not rows:
        return
    offset = _table_start(meta, table)
    row_size = _table_row_size(meta, table)
    rows = min(rows, _rows_the_stream_can_hold(meta, offset, row_size))
    for rid in range(1, rows + 1):
        yield rid, offset
        offset += row_size


def _rows_the_stream_can_hold(meta: _MetaCtx, offset: int, row_size: int) -> int:
    """How many rows are actually there, whatever the header claims.

    The row count is a number out of the assembly, and the callers of this
    materialise the whole table into a list before paging it. A TypeDef table
    declaring 0x7fffffff rows therefore ran for more than twenty-five seconds
    and took 1.2 GB of heap with it, from a 60 KB file and a request for twenty
    items. The rows cannot extend past the #~ stream that holds them, so that
    is the bound: derived from the file rather than picked.
    """
    if row_size <= 0 or offset >= len(meta.tables):
        return 0
    return (len(meta.tables) - offset) // row_size


def _iter_typedefs(meta: _MetaCtx) -> Iterable[JsonObject]:
    for rid, at in _iter_table_rows(meta, _TBL_TYPEDEF):
        name_idx, nsz = _read_index(meta.tables, at + 4, meta.string_index_size)
        ns_idx, _ = _read_index(meta.tables, at + 4 + nsz, meta.string_index_size)
        yield {
            "token": 0x02000000 | rid,
            "rid": rid,
            "name": _string_at(meta, name_idx),
            "namespace": _string_at(meta, ns_idx),
        }


def _iter_methoddefs(meta: _MetaCtx) -> Iterable[JsonObject]:
    for rid, at in _iter_table_rows(meta, _TBL_METHODDEF):
        rva = int.from_bytes(meta.tables[at : at + 4], "little")
        name_at = at + 4 + 2 + 2
        name_idx, _ = _read_index(meta.tables, name_at, meta.string_index_size)
        yield {
            "token": 0x06000000 | rid,
            "rid": rid,
            "name": _string_at(meta, name_idx),
            "rva": rva,
        }


def _iter_fields(meta: _MetaCtx) -> Iterable[JsonObject]:
    for rid, at in _iter_table_rows(meta, _TBL_FIELD):
        name_idx, _ = _read_index(meta.tables, at + 2, meta.string_index_size)
        yield {
            "token": 0x04000000 | rid,
            "rid": rid,
            "name": _string_at(meta, name_idx),
        }


def _iter_resources(meta: _MetaCtx) -> Iterable[JsonObject]:
    for rid, at in _iter_table_rows(meta, _TBL_MANIFESTRESOURCE):
        offset = int.from_bytes(meta.tables[at : at + 4], "little")
        flags = int.from_bytes(meta.tables[at + 4 : at + 8], "little")
        name_idx, _ = _read_index(meta.tables, at + 8, meta.string_index_size)
        yield {
            "token": 0x28000000 | rid,
            "rid": rid,
            "name": _string_at(meta, name_idx),
            "offset": offset,
            "flags": flags,
        }


def _iter_memberrefs(meta: _MetaCtx) -> Iterable[JsonObject]:
    for rid, at in _iter_table_rows(meta, _TBL_MEMBERREF):
        cls_size = _coded_index_size(meta.row_counts, (0x02, 0x01, 0x1A, 0x06, 0x1B), 3)
        name_idx, _ = _read_index(meta.tables, at + cls_size, meta.string_index_size)
        yield {
            "token": 0x0A000000 | rid,
            "rid": rid,
            "name": _string_at(meta, name_idx),
            "class_coded_index": int.from_bytes(meta.tables[at : at + cls_size], "little"),
        }


def _iter_strings_heap(meta: _MetaCtx) -> Iterable[JsonObject]:
    data = meta.strings
    if not data:
        return
    i = 1
    count = 0
    while i < len(data):
        end = data.find(b"\0", i)
        if end < 0:
            end = len(data)
        raw = data[i:end]
        if raw:
            count += 1
            yield {"index": i, "value": raw.decode("utf-8", errors="replace")}
        i = end + 1
        if count >= 10000:
            break


def _read_method_body(meta: _MetaCtx, rva: int, *, max_bytes: int) -> JsonObject:
    try:
        file_off = pe_mod._rva_to_offset(meta.layout, rva, size=1)  # noqa: SLF001
    except PeFormatError as exc:
        raise DotnetInspectError("not_found", f"method RVA not mappable: {rva:#x}") from exc
    data = meta.pe_data
    if file_off >= len(data):
        raise DotnetInspectError("not_found", f"method RVA out of file: {rva:#x}")
    first = data[file_off]
    if (first & 0x03) == 0x02:
        code_size = first >> 2
        il_start = file_off + 1
        header: JsonObject = {"format": "tiny", "code_size": code_size}
    else:
        if file_off + 12 > len(data):
            raise DotnetInspectError("not_found", "fat method header truncated")
        flags = int.from_bytes(data[file_off : file_off + 2], "little")
        max_stack = int.from_bytes(data[file_off + 2 : file_off + 4], "little")
        code_size = int.from_bytes(data[file_off + 4 : file_off + 8], "little")
        local_sig = int.from_bytes(data[file_off + 8 : file_off + 12], "little")
        il_start = file_off + 12
        header = {
            "format": "fat",
            "flags": flags,
            "max_stack": max_stack,
            "code_size": code_size,
            "local_var_sig_tok": local_sig,
        }
    truncated = code_size > max_bytes
    take = min(code_size, max_bytes)
    il = data[il_start : il_start + take]
    return {"header": header, "il": il, "il_len": code_size, "truncated": truncated}


def _read_operand(il: bytes, at: int, imm: int, name: str) -> tuple[int | None, bool]:
    """Read an ``imm``-byte inline operand, honouring ECMA-335 signedness.

    Returns (value, ok); ok is False when the operand runs past the IL, which
    the caller turns into a bounded ``partial`` stop rather than a wild read.
    """
    if imm == 0:
        return None, True
    if at + imm > len(il):
        return None, False
    return int.from_bytes(il[at : at + imm], "little", signed=name in _SIGNED_OPERANDS), True


def _disassemble_il(il: bytes, *, max_insns: int) -> tuple[list[JsonObject], bool]:
    rebuilt: list[JsonObject] = []
    i = 0
    partial = False
    n = len(il)
    while i < n and len(rebuilt) < max_insns:
        start = i
        op = il[i]
        if op == 0xFE:
            if i + 1 >= n:
                partial = True
                break
            second = il[i + 1]
            info = _OP2.get(second)
            if info is None:
                rebuilt.append({"ip": start, "mnemonic": f"op_fe_{second:02x}", "operand": None})
                i += 2
                partial = True
                continue
            name, imm = info
            operand, ok = _read_operand(il, i + 2, imm, name)
            if not ok:
                partial = True
                break
            rebuilt.append({"ip": start, "mnemonic": name, "operand": operand})
            i += 2 + imm
            continue
        if op == _SWITCH_OP:
            # switch is uint32 count N followed by N signed int32 jump targets;
            # a bad count that overran the IL used to be impossible to skip, so
            # bound it to what the IL can actually hold.
            if i + 5 > n:
                partial = True
                break
            count = int.from_bytes(il[i + 1 : i + 5], "little")
            body = i + 5
            if count < 0 or body + 4 * count > n:
                rebuilt.append({"ip": start, "mnemonic": "switch", "operand": None})
                partial = True
                break
            targets = [
                int.from_bytes(il[body + 4 * k : body + 4 * k + 4], "little", signed=True)
                for k in range(count)
            ]
            rebuilt.append({"ip": start, "mnemonic": "switch", "operand": targets})
            i = body + 4 * count
            continue
        info = _OP1.get(op)
        if info is None:
            # Unknown opcode: its operand width is unknown too, so alignment
            # past here is a guess -- say so instead of decoding operand bytes
            # as if they were the next instruction.
            rebuilt.append({"ip": start, "mnemonic": f"op_{op:02x}", "operand": None})
            i += 1
            partial = True
            continue
        name, imm = info
        operand, ok = _read_operand(il, i + 1, imm, name)
        if not ok:
            partial = True
            break
        rebuilt.append({"ip": start, "mnemonic": name, "operand": operand})
        i += 1 + imm
    if len(rebuilt) >= max_insns and i < n:
        partial = True
    return rebuilt, partial
