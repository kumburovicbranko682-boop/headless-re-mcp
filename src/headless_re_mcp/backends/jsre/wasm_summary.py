"""Dependency-free structured read of a WebAssembly module's shape.

wasm.wat and wasm.info shell out to wabt (wasm2wat / wasm-objdump) and hand
back a wall of text an agent must then grep -- and when wabt is not installed
the whole wasm line is capability_unavailable. This reads the module's binary
sections directly: no wabt, no subprocess, pure Python. It returns the two
things a triage pass wants structured -- the import section (the host interface
the module depends on: ``env.*`` JS glue, ``wasi_snapshot_preview1.*`` syscalls)
and the export section (its entry points) -- plus a one-line-per-section
overview and the start function when present.

Only the section framing and the import/export/start sections are decoded;
every other section (type, code, data, ...) is skipped by its declared size, so
a huge code section costs nothing here. Every read is bounds-checked against the
buffer and the section, LEB128 integers are length-bounded, the listed vectors
are capped, and the section walk is counted, so a malformed or hostile module
raises WasmParseError rather than looping, over-reading, or over-allocating.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any

JsonObject = dict[str, Any]

WASM_MAGIC = b"\x00asm"

# external_kind (import/export descriptor tag) -> readable name.
_KIND_NAMES = {0: "func", 1: "table", 2: "memory", 3: "global"}

_SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}

# A single import/export name; real ones are short identifiers. A length past
# this is a malformed/hostile module, refused before allocating the slice.
_MAX_NAME_BYTES = 4096
# Section records to enumerate before giving up: a real module has a dozen or so,
# and each record consumes >=2 bytes so a 16 MiB module cannot hold many, but the
# count is bounded explicitly rather than trusting that.
_MAX_SECTIONS = 4096
# LEB128 unsigned: 10 bytes covers a u64; a u32 index/size uses at most 5. Ten is
# the ceiling so a run of 0x80 continuation bytes cannot spin the decoder.
_MAX_LEB_BYTES = 10


class WasmParseError(ValueError):
    """The bytes are not a WebAssembly module we can read structurally."""


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Read one unsigned LEB128 integer, returning (value, next_pos)."""
    result = 0
    shift = 0
    read = 0
    while True:
        if pos >= len(data):
            raise WasmParseError("truncated LEB128 integer")
        byte = data[pos]
        pos += 1
        read += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        if read >= _MAX_LEB_BYTES:
            raise WasmParseError("LEB128 integer too long")
        shift += 7


def _name(data: bytes, pos: int) -> tuple[str, int]:
    """Read a length-prefixed UTF-8 name, returning (text, next_pos)."""
    length, pos = _uleb(data, pos)
    if length > _MAX_NAME_BYTES:
        raise WasmParseError("name length exceeds bound")
    end = pos + length
    if end > len(data):
        raise WasmParseError("name overruns module")
    return data[pos:end].decode("utf-8", "replace"), end


def _skip_limits(data: bytes, pos: int) -> int:
    """Advance past a limits record (flags, min, and max when the flag is set)."""
    flags, pos = _uleb(data, pos)
    _min, pos = _uleb(data, pos)
    if flags & 0x01:
        _max, pos = _uleb(data, pos)
    return pos


def _need(pos: int, count: int, end: int, what: str) -> None:
    if pos + count > end:
        raise WasmParseError(f"{what} overruns section")


def _parse_imports(
    data: bytes, pos: int, end: int, *, cap: int
) -> tuple[list[JsonObject], int]:
    count, pos = _uleb(data, pos)
    items: list[JsonObject] = []
    parsed = 0
    while parsed < count and pos < end:
        if len(items) >= cap:
            # A full page is collected; the declared vector length is the total.
            break
        module, pos = _name(data, pos)
        field, pos = _name(data, pos)
        _need(pos, 1, end, "import kind")
        kind = data[pos]
        pos += 1
        entry: JsonObject = {
            "module": module,
            "name": field,
            "kind": _KIND_NAMES.get(kind, str(kind)),
        }
        if kind == 0:  # func: type index
            type_index, pos = _uleb(data, pos)
            entry["type_index"] = type_index
        elif kind == 1:  # table: reftype byte then limits
            _need(pos, 1, end, "table reftype")
            pos = _skip_limits(data, pos + 1)
        elif kind == 2:  # memory: limits
            pos = _skip_limits(data, pos)
        elif kind == 3:  # global: valtype byte + mutability byte
            _need(pos, 2, end, "global type")
            pos += 2
        else:
            raise WasmParseError(f"unknown import kind {kind}")
        if pos > end:
            raise WasmParseError("import entry overruns section")
        items.append(entry)
        parsed += 1
    return items, count


def _parse_exports(
    data: bytes, pos: int, end: int, *, cap: int
) -> tuple[list[JsonObject], int]:
    count, pos = _uleb(data, pos)
    items: list[JsonObject] = []
    parsed = 0
    while parsed < count and pos < end:
        if len(items) >= cap:
            break
        name, pos = _name(data, pos)
        _need(pos, 1, end, "export kind")
        kind = data[pos]
        pos += 1
        index, pos = _uleb(data, pos)
        if pos > end:
            raise WasmParseError("export entry overruns section")
        items.append(
            {"name": name, "kind": _KIND_NAMES.get(kind, str(kind)), "index": index}
        )
        parsed += 1
    return items, count


def summarize(data: bytes, *, max_imports: int = 1000, max_exports: int = 1000) -> JsonObject:
    """Parse a wasm module's shape: version, sections, imports, exports, start.

    Raises WasmParseError when the bytes are not a module we can read. The
    imports/exports lists are capped at ``max_imports``/``max_exports``; the
    ``*_total`` fields carry the declared vector length so a capped page is not
    read as the whole section.
    """
    if len(data) < 8 or data[:4] != WASM_MAGIC:
        raise WasmParseError("not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    pos = 8
    total_len = len(data)
    sections: list[JsonObject] = []
    imports: list[JsonObject] = []
    exports: list[JsonObject] = []
    imports_total = 0
    exports_total = 0
    start_function: int | None = None
    records = 0
    while pos < total_len:
        records += 1
        if records > _MAX_SECTIONS:
            raise WasmParseError("too many sections")
        sec_id = data[pos]
        pos += 1
        size, pos = _uleb(data, pos)
        body = pos
        end = pos + size
        if end > total_len:
            raise WasmParseError("section overruns module")
        record: JsonObject = {
            "id": sec_id,
            "name": _SECTION_NAMES.get(sec_id, str(sec_id)),
            "size": size,
        }
        if sec_id == 0:  # custom: a name, then opaque bytes -- surface the name
            with suppress(WasmParseError):
                record["custom_name"], _ = _name(data, body)
        sections.append(record)
        if sec_id == 2:
            imports, imports_total = _parse_imports(data, body, end, cap=max_imports)
        elif sec_id == 7:
            exports, exports_total = _parse_exports(data, body, end, cap=max_exports)
        elif sec_id == 8:
            start_function, _ = _uleb(data, body)
        pos = end
    result: JsonObject = {
        "version": version,
        "sections": sections,
        "imports": imports,
        "imports_count": len(imports),
        "imports_total": imports_total,
        "imports_truncated": imports_total > len(imports),
        "exports": exports,
        "exports_count": len(exports),
        "exports_total": exports_total,
        "exports_truncated": exports_total > len(exports),
    }
    if start_function is not None:
        result["start_function"] = start_function
    return result
