"""Structured WebAssembly module summary parsed straight from the binary.

wasm.wat / wasm.info shell out to wabt and hand back a text blob; a caller who
only wants "what does this module import from the host, and what does it export"
had to install wabt and then grep the objdump text. This reads the module's
section table directly -- pure Python, no external tool -- so the import/export
surface (the JS/WASI interop boundary and the callable exports) is available as
data even when wabt is not configured.

Only the sections a summary needs are decoded (type/import/function/memory/
export/start plus custom-section names); every other section is skipped by its
declared length, and each section body is sliced to its own bounds so a
malformed length can never read past the module. Hostile input is expected:
truncation, over-long LEB128 and bad magic all raise ``invalid_params`` rather
than crash, matching the other jsre adapters.
"""

from __future__ import annotations

import contextlib
import struct
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.jsre.client import JsReError, _require_existing_file

JsonObject = dict[str, Any]

_WASM_MAGIC = b"\x00asm"
# The value types a function signature is built from. The number encoding is
# the one-byte form used in the type section: the four numeric types, the two
# reference types, and v128. An unknown byte (a type from a newer proposal) is
# reported verbatim as "type 0x<n>" rather than guessed at, mirroring how the
# import/export decoder reports an unknown external kind.
_VALTYPE = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
# func/table/memory/global -- the four external kinds an import or export can
# name. Anything else means the module is malformed or from a newer proposal we
# do not claim to understand, so it is reported verbatim as "kind <n>".
_EXTERNAL_KIND = {0: "func", 1: "table", 2: "memory", 3: "global"}
# The standard WebAssembly section ids. An id outside this map is reported as
# "section <n>" rather than guessed at, so a module using a newer proposal's
# section is still laid out rather than rejected.
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
    13: "tag",
}
# Imports and exports are listed, so they are capped and the cut is announced,
# exactly like the r2 item lists. Everything else is only counted.
_MAX_ITEMS = 4096
# A single LEB128 integer in a 32-bit module is at most 5 bytes; 64-bit memory
# indices at most 10. Ten 7-bit groups (70 bits) is a generous ceiling that
# still refuses a maliciously padded run of 0x80 bytes.
_MAX_LEB_GROUPS = 10
# wasm.strings defaults: a 4-char floor drops the 1-3 byte noise a raw scan of
# packed memory throws off, and each string is clipped so one giant blob (a
# base64 payload, an embedded file) cannot dominate the reply.
_MIN_STRING_DEFAULT = 4
_MAX_STRING_LEN = 8192


class _Cursor:
    """A bounds-checked read cursor over one bytes object."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise JsReError("invalid_params", "wasm truncated: expected another byte")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise JsReError("invalid_params", "wasm truncated: expected more bytes")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def uleb(self) -> int:
        result = 0
        shift = 0
        groups = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            groups += 1
            if not byte & 0x80:
                return result
            if groups >= _MAX_LEB_GROUPS:
                raise JsReError("invalid_params", "wasm LEB128 integer too long")
            shift += 7

    def sleb(self) -> int:
        result = 0
        shift = 0
        groups = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            groups += 1
            if not byte & 0x80:
                if byte & 0x40:  # sign bit set: the value is negative
                    result |= -(1 << shift)
                return result
            if groups >= _MAX_LEB_GROUPS:
                raise JsReError("invalid_params", "wasm LEB128 integer too long")

    def name(self) -> str:
        length = self.uleb()
        return self.take(length).decode("utf-8", errors="replace")


def _read_limits(cursor: _Cursor) -> JsonObject:
    """A limits record: flags byte, minimum, and a maximum only when bit 0 is set."""
    flags = cursor.byte()
    minimum = cursor.uleb()
    limits: JsonObject = {"initial": minimum}
    if flags & 0x01:
        limits["maximum"] = cursor.uleb()
    return limits


def _parse_imports(body: _Cursor) -> tuple[list[JsonObject], int, int]:
    """Import section (id 2): (collected, total, imported_function_count)."""
    total = body.uleb()
    collected: list[JsonObject] = []
    imported_funcs = 0
    for index in range(total):
        module = body.name()
        field = body.name()
        kind_byte = body.byte()
        kind = _EXTERNAL_KIND.get(kind_byte, f"kind {kind_byte}")
        # The import descriptor's tail differs by kind; consume it so the cursor
        # stays aligned for the next import even when we do not surface it.
        if kind_byte == 0:
            body.uleb()  # type index
            imported_funcs += 1
        elif kind_byte == 1:
            body.byte()  # reftype
            _read_limits(body)
        elif kind_byte == 2:
            _read_limits(body)
        elif kind_byte == 3:
            body.byte()  # value type
            body.byte()  # mutability
        else:
            raise JsReError("invalid_params", "wasm import has an unknown external kind")
        if index < _MAX_ITEMS:
            collected.append({"module": module, "name": field, "kind": kind})
    return collected, total, imported_funcs


def _parse_exports(body: _Cursor) -> tuple[list[JsonObject], int]:
    """Export section (id 7): (collected, total)."""
    total = body.uleb()
    collected: list[JsonObject] = []
    for index in range(total):
        field = body.name()
        kind_byte = body.byte()
        kind = _EXTERNAL_KIND.get(kind_byte, f"kind {kind_byte}")
        item_index = body.uleb()
        if index < _MAX_ITEMS:
            collected.append({"name": field, "kind": kind, "index": item_index})
    return collected, total


def summarize_wasm_bytes(data: bytes) -> JsonObject:
    """Summarize a WebAssembly module from its raw bytes."""
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    version = int.from_bytes(data[4:8], "little")
    cursor = _Cursor(data)
    cursor.pos = 8

    imports: list[JsonObject] = []
    exports: list[JsonObject] = []
    imports_total = 0
    exports_total = 0
    imported_funcs = 0
    memory: JsonObject | None = None
    has_start = False
    custom_sections: list[str] = []
    counts = {
        "types": 0,
        "functions": 0,
        "tables": 0,
        "globals": 0,
        "memories": 0,
        "data_segments": 0,
        "elements": 0,
    }

    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 0:  # custom
            if not body.eof:
                custom_sections.append(body.name())
        elif section_id == 1:  # type
            counts["types"] = body.uleb()
        elif section_id == 2:  # import
            imports, imports_total, imported_funcs = _parse_imports(body)
        elif section_id == 3:  # function
            counts["functions"] = body.uleb()
        elif section_id == 4:  # table
            counts["tables"] = body.uleb()
        elif section_id == 5:  # memory
            counts["memories"] = body.uleb()
            if counts["memories"] > 0:
                memory = _read_limits(body)
        elif section_id == 6:  # global
            counts["globals"] = body.uleb()
        elif section_id == 7:  # export
            exports, exports_total = _parse_exports(body)
        elif section_id == 8:  # start
            body.uleb()  # start function index
            has_start = True
        elif section_id == 9:  # element
            counts["elements"] = body.uleb()
        elif section_id == 11:  # data
            counts["data_segments"] = body.uleb()
        # 10 (code), 12 (data count) and any future id are skipped by length.

    summary: JsonObject = {
        "version": version,
        "imports": imports,
        "import_count": len(imports),
        "exports": exports,
        "export_count": len(exports),
        "memory": memory,
        "has_start": has_start,
        "custom_sections": custom_sections,
        "counts": {**counts, "imported_functions": imported_funcs},
    }
    if imports_total > len(imports):
        summary["imports_truncated"] = True
        summary["imports_total"] = imports_total
        summary["imports_limit"] = _MAX_ITEMS
    if exports_total > len(exports):
        summary["exports_truncated"] = True
        summary["exports_total"] = exports_total
        summary["exports_limit"] = _MAX_ITEMS
    return summary


def summarize_wasm(path: Path) -> JsonObject:
    """Summarize the module at ``path`` (applies the shared 16 MiB input cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return summarize_wasm_bytes(data)


def _skip_const_expr(cursor: _Cursor) -> int | None:
    """Consume a constant init-expr, returning its base offset when it is one.

    A data segment's offset is a constant expression -- in every real module a
    single ``i32.const N`` (or ``i64.const`` on memory64, or ``global.get`` for
    a relocatable base) followed by the ``end`` opcode 0x0B. The literal base is
    returned so a recovered string can be given its linear-memory address; a
    global-relative or empty expr yields None. Anything unexpected is skipped by
    reading to the end marker rather than desyncing the parse.
    """
    opcode = cursor.byte()
    base: int | None = None
    if opcode in (0x41, 0x42):  # i32.const / i64.const
        base = cursor.sleb()
    elif opcode == 0x23:  # global.get
        cursor.uleb()
    elif opcode == 0x0B:  # empty expr (defensive: not valid, but do not crash)
        return None
    end = cursor.byte()
    if end != 0x0B:
        # An unexpected multi-instruction expr: read to the end marker so the
        # cursor stays aligned for the segment bytes that follow.
        while cursor.byte() != 0x0B:
            pass
    return base


def _parse_data_segments(body: _Cursor) -> list[tuple[int | None, bytes]]:
    """Data section (id 11): a list of (base_offset_or_None, raw_bytes) segments."""
    count = body.uleb()
    segments: list[tuple[int | None, bytes]] = []
    for _ in range(count):
        flags = body.uleb()
        if flags == 0:  # active, memory 0, offset expr
            base = _skip_const_expr(body)
            segments.append((base, body.take(body.uleb())))
        elif flags == 1:  # passive: no memory, no offset
            segments.append((None, body.take(body.uleb())))
        elif flags == 2:  # active, explicit memory index, offset expr
            body.uleb()  # memory index
            base = _skip_const_expr(body)
            segments.append((base, body.take(body.uleb())))
        else:
            raise JsReError("invalid_params", "wasm data segment has an unknown flag")
    return segments


def _scan_printable(raw: bytes, min_length: int, max_len: int) -> list[tuple[int, str]]:
    """Maximal runs of printable ASCII (0x20..0x7E) of at least ``min_length``."""
    out: list[tuple[int, str]] = []
    start: int | None = None
    run = bytearray()
    for index, byte in enumerate(raw):
        if 0x20 <= byte <= 0x7E:
            if start is None:
                start = index
            run.append(byte)
            if len(run) >= max_len:
                out.append((start, run.decode("ascii")))
                start = None
                run = bytearray()
        else:
            if start is not None and len(run) >= min_length:
                out.append((start, run.decode("ascii")))
            start = None
            run = bytearray()
    if start is not None and len(run) >= min_length:
        out.append((start, run.decode("ascii")))
    return out


def extract_wasm_strings_bytes(
    data: bytes, *, min_length: int = _MIN_STRING_DEFAULT, contains: str | None = None
) -> JsonObject:
    """Extract printable strings from a module's data segments.

    Compiled WASM keeps its string literals (URLs, keys, messages, format
    strings) in the data section that initializes linear memory. This walks the
    data segments -- pure Python, no wabt -- and scans each for printable ASCII
    runs, giving each a segment index and, when the segment's offset is a literal
    constant, its linear-memory address. Only the data section is read; code and
    everything else is skipped by length.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    floor = max(1, int(min_length))
    needle = contains.casefold() if contains else None
    cursor = _Cursor(data)
    cursor.pos = 8

    segments: list[tuple[int | None, bytes]] = []
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 11:  # data
            segments = _parse_data_segments(body)
        # Every other section is skipped by its declared length.

    collected: list[JsonObject] = []
    total = 0
    scan_capped = False
    for seg_index, (base, seg_bytes) in enumerate(segments):
        for pos, text in _scan_printable(seg_bytes, floor, _MAX_STRING_LEN):
            if needle is not None and needle not in text.casefold():
                continue
            total += 1
            if len(collected) >= _MAX_ITEMS:
                scan_capped = True
                continue
            item: JsonObject = {"string": text, "segment": seg_index}
            if base is not None:
                item["addr"] = base + pos
            collected.append(item)

    result: JsonObject = {
        "strings": collected,
        "count": len(collected),
        "total": total,
        "data_segments": len(segments),
        "min_length": floor,
        "scan_capped": scan_capped,
    }
    if needle is not None:
        result["filtered"] = True
        result["query"] = contains
    return result


def extract_wasm_strings(
    path: Path, *, min_length: int = _MIN_STRING_DEFAULT, contains: str | None = None
) -> JsonObject:
    """Extract data-segment strings from the module at ``path`` (16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return extract_wasm_strings_bytes(data, min_length=min_length, contains=contains)


def _find_name_section(data: bytes) -> _Cursor | None:
    """The body of the ``name`` custom section, positioned past its name string.

    A module carries function names only in the custom section literally named
    ``"name"``; other custom sections (producers, dylink, source maps) are
    skipped. Returns None when the module is stripped of names. Each section
    body is sliced to its own declared bounds, so a bad length cannot read past
    the module.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    cursor = _Cursor(data)
    cursor.pos = 8
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 0 and not body.eof and body.name() == "name":
            return body  # now positioned at the first name subsection
    return None


def extract_wasm_names_bytes(data: bytes, *, contains: str | None = None) -> JsonObject:
    """Recover the module and function names from the ``name`` custom section.

    The name section is WASM's debug symbol table: a compiler that keeps it
    (or a dev build) maps each function index to a human-readable name, so an
    internal function that never made the export table still has a name here.
    This is the WASM parallel of a native symbol table -- pure Python, no wabt.
    Only the module-name (subsection 0) and function-names (subsection 1)
    subsections are decoded; local/label/type name subsections are skipped by
    their declared size. ``has_name_section`` is false for a stripped module,
    which is a different answer from a present-but-empty table.
    """
    name_body = _find_name_section(data)
    needle = contains.casefold() if contains else None
    module_name: str | None = None
    functions: list[JsonObject] = []
    function_total = 0
    scan_capped = False
    if name_body is not None:
        while not name_body.eof:
            sub_id = name_body.byte()
            sub_len = name_body.uleb()
            sub = _Cursor(name_body.take(sub_len))
            if sub_id == 0:  # module name (a single name)
                if not sub.eof:
                    module_name = sub.name()
            elif sub_id == 1:  # function names: a namemap of (index, name)
                # The filter runs during the scan, so _MAX_ITEMS bounds matches
                # rather than the pre-filter set -- a named function past the cap
                # is still found, exactly like wasm.strings. The loop is bounded
                # by the subsection's own bytes: each entry consumes >= 2 bytes,
                # so a lying count runs out of data and stops.
                count = sub.uleb()
                for _ in range(count):
                    index = sub.uleb()
                    fname = sub.name()
                    if needle is not None and needle not in fname.casefold():
                        continue
                    function_total += 1
                    if len(functions) >= _MAX_ITEMS:
                        scan_capped = True
                        continue
                    functions.append({"index": index, "name": fname})
            # Every other subsection is skipped by its declared size.
    result: JsonObject = {
        "has_name_section": name_body is not None,
        "module_name": module_name,
        "functions": functions,
        "count": len(functions),
        "total": function_total,
        "scan_capped": scan_capped,
    }
    if needle is not None:
        result["filtered"] = True
        result["query"] = contains
    return result


def extract_wasm_names(path: Path, *, contains: str | None = None) -> JsonObject:
    """Recover names from the module at ``path`` (applies the shared 16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return extract_wasm_names_bytes(data, contains=contains)


def extract_wasm_sections_bytes(data: bytes) -> JsonObject:
    """Lay out a module's section table: id, name, size and file offset.

    wasm.summary counts what is inside the sections; this is the map of the
    sections themselves -- where each one starts in the file and how big it is,
    the WASM parallel of a native section table. It reads the section framing
    directly in pure Python (no wabt) and is where you spot an oversized custom
    section hiding a payload, or find the byte offset of the data/code section
    to carve. Each section body is sliced to its own bounds, so a bad length
    cannot read past the module.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    version = int.from_bytes(data[4:8], "little")
    cursor = _Cursor(data)
    cursor.pos = 8

    collected: list[JsonObject] = []
    total = 0
    for section_id, body_offset, section_len, body in _walk_sections(cursor):
        total += 1
        if len(collected) >= _MAX_ITEMS:
            continue
        entry: JsonObject = {
            "id": section_id,
            "name": _SECTION_NAMES.get(section_id, f"section {section_id}"),
            "size": section_len,
            "offset": body_offset,
        }
        if section_id == 0 and not body.eof:
            # A custom section's body is a name followed by an opaque payload;
            # surface the name and how many bytes the payload itself is, so a
            # fat "custom" entry is not mistaken for a fat standard section.
            try:
                entry["custom_name"] = body.name()
                entry["payload_size"] = section_len - body.pos
            except JsReError:
                pass
        collected.append(entry)

    result: JsonObject = {
        "version": version,
        "sections": collected,
        "count": len(collected),
        "total": total,
    }
    if total > len(collected):
        result["sections_truncated"] = True
        result["sections_total"] = total
        result["sections_limit"] = _MAX_ITEMS
    return result


def _walk_sections(cursor: _Cursor) -> list[tuple[int, int, int, _Cursor]]:
    """Yield (section_id, body_file_offset, body_len, body_cursor) for each section.

    Reading the id byte and the LEB length advances the cursor to the body, so
    ``cursor.pos`` at that point is the body's absolute file offset. ``take``
    slices the body to its declared length, keeping every downstream read inside
    the section even when the length is a lie.
    """
    out: list[tuple[int, int, int, _Cursor]] = []
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body_offset = cursor.pos
        body = _Cursor(cursor.take(section_len))
        out.append((section_id, body_offset, section_len, body))
    return out


def extract_wasm_sections(path: Path) -> JsonObject:
    """Lay out the section table of the module at ``path`` (shared 16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return extract_wasm_sections_bytes(data)


def _valtype(cursor: _Cursor) -> str:
    """One value type byte, decoded to its name (unknown bytes reported verbatim)."""
    byte = cursor.byte()
    return _VALTYPE.get(byte, f"type 0x{byte:02x}")


def _parse_functypes(body: _Cursor) -> list[tuple[list[str], list[str]] | None]:
    """Type section (id 1): each functype's (params, results) by type index.

    Only functypes (form byte 0x60) are decoded. A non-0x60 form is a struct/
    array type from the GC proposal whose body we cannot length-skip, so decoding
    stops there: a ``None`` placeholder keeps earlier indices valid and any
    function whose type index lands past it is reported ``signature_unknown``
    rather than mis-decoded. The body is sliced to its own bounds, so a bad
    length cannot read past the section.
    """
    total = body.uleb()
    types: list[tuple[list[str], list[str]] | None] = []
    for _ in range(total):
        form = body.byte()
        if form != 0x60:
            types.append(None)
            break
        params = [_valtype(body) for _ in range(body.uleb())]
        results = [_valtype(body) for _ in range(body.uleb())]
        types.append((params, results))
    return types


def _parse_import_funcs(body: _Cursor) -> tuple[list[tuple[str, str, int]], int]:
    """Import section (id 2): (collected imported funcs, total imported funcs).

    Imported functions occupy the low function-index space, before the module's
    own defined functions, so they must be walked to keep the global function
    index aligned with the name section. Each non-func import's descriptor is
    consumed by kind so the cursor stays aligned; only funcs are collected, as
    (module, field, type_index), capped at ``_MAX_ITEMS`` while the true count
    is still returned.
    """
    total = body.uleb()
    collected: list[tuple[str, str, int]] = []
    func_total = 0
    for _ in range(total):
        module = body.name()
        field = body.name()
        kind_byte = body.byte()
        if kind_byte == 0:
            type_index = body.uleb()
            func_total += 1
            if len(collected) < _MAX_ITEMS:
                collected.append((module, field, type_index))
        elif kind_byte == 1:
            body.byte()  # reftype
            _read_limits(body)
        elif kind_byte == 2:
            _read_limits(body)
        elif kind_byte == 3:
            body.byte()  # value type
            body.byte()  # mutability
        else:
            raise JsReError("invalid_params", "wasm import has an unknown external kind")
    return collected, func_total


def _parse_function_section(body: _Cursor, cap: int) -> tuple[list[int], int]:
    """Function section (id 3): (type indices of defined funcs, total defined).

    The list is capped at ``cap`` (only the emitted head is needed), but every
    entry is still consumed so a lying count runs out of the bounded body and
    raises rather than silently under-reporting.
    """
    total = body.uleb()
    indices: list[int] = []
    for index in range(total):
        value = body.uleb()
        if index < cap:
            indices.append(value)
    return indices, total


def _function_name_map(data: bytes) -> dict[int, str]:
    """Global function index -> name from the ``name`` custom section (best effort).

    Reuses the same name-section locator as wasm.names; only the function-names
    subsection (id 1) is read. A stripped or corrupt name section yields an
    empty map -- the signatures are the primary data, names are a bonus -- so a
    bad name section never sinks the function listing.
    """
    names: dict[int, str] = {}
    name_body = _find_name_section(data)
    if name_body is None:
        return names
    while not name_body.eof:
        sub_id = name_body.byte()
        sub_len = name_body.uleb()
        sub = _Cursor(name_body.take(sub_len))
        if sub_id == 1:  # function names: a namemap of (index, name)
            count = sub.uleb()
            for _ in range(count):
                index = sub.uleb()
                fname = sub.name()
                names.setdefault(index, fname)
            break
    return names


def _function_entry(
    index: int,
    kind: str,
    type_index: int,
    types: list[tuple[list[str], list[str]] | None],
    names: dict[int, str],
    *,
    module: str | None = None,
    import_name: str | None = None,
) -> JsonObject:
    """One function's record: index, kind, resolved signature, and any name."""
    entry: JsonObject = {"index": index, "kind": kind, "type_index": type_index}
    signature = types[type_index] if 0 <= type_index < len(types) else None
    if signature is None:
        entry["params"] = []
        entry["results"] = []
        entry["signature_unknown"] = True
    else:
        entry["params"] = list(signature[0])
        entry["results"] = list(signature[1])
    name = names.get(index)
    if name is not None:
        entry["name"] = name
    if module is not None:
        entry["module"] = module
    if import_name is not None:
        entry["import_name"] = import_name
    return entry


def _function_matches(entry: JsonObject, needle: str | None) -> bool:
    """Case-insensitive substring match over a function's name/module fields."""
    if needle is None:
        return True
    haystack = " ".join(
        str(entry.get(key, ""))
        for key in ("name", "import_name", "module")
    ).casefold()
    return needle in haystack


def list_wasm_functions_bytes(data: bytes, *, contains: str | None = None) -> JsonObject:
    """List a module's functions with resolved signatures (imported and defined).

    wasm.summary only counts functions and wasm.names only maps an index to a
    name; neither tells you a function's signature or which functions are
    imported from the host versus defined in the module. This joins the type
    section (the param/result value types), the import section (the imported
    functions, which occupy the low index space) and the function section (the
    module's own functions) into one addressed table, then attaches the name
    from the ``name`` custom section when present. It is the WASM parallel of a
    native function/symbol table with signatures, parsed in pure Python.

    Each entry carries index (the global function index, imports first), kind
    (imported/defined), type_index, params and results (value-type names),
    plus name when the name section has one and, for an imported function,
    module and import_name. signature_unknown is set when the type index cannot
    be resolved (a truncated type section or a GC type this parser stops at).
    Only the type/import/function/name sections are read; every other section is
    skipped by its declared length.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    needle = contains.casefold() if contains else None
    cursor = _Cursor(data)
    cursor.pos = 8

    types: list[tuple[list[str], list[str]] | None] = []
    imported: list[tuple[str, str, int]] = []
    imported_total = 0
    defined_indices: list[int] = []
    defined_total = 0
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 1:  # type
            types = _parse_functypes(body)
        elif section_id == 2:  # import
            imported, imported_total = _parse_import_funcs(body)
        elif section_id == 3:  # function
            defined_indices, defined_total = _parse_function_section(body, _MAX_ITEMS)
        # Every other section is skipped by its declared length.

    # The name section is a bonus join; a corrupt one must not fail the listing.
    names: dict[int, str] = {}
    with contextlib.suppress(JsReError):
        names = _function_name_map(data)

    functions: list[JsonObject] = []
    matched = 0
    emission_capped = False

    def _consider(entry: JsonObject) -> None:
        nonlocal matched, emission_capped
        if not _function_matches(entry, needle):
            return
        matched += 1
        if len(functions) >= _MAX_ITEMS:
            emission_capped = True
            return
        functions.append(entry)

    for position, (module, field, type_index) in enumerate(imported):
        _consider(
            _function_entry(
                position, "imported", type_index, types, names,
                module=module, import_name=field,
            )
        )
    for offset, type_index in enumerate(defined_indices):
        _consider(
            _function_entry(imported_total + offset, "defined", type_index, types, names)
        )

    # The import/function sections are collected only up to the cap, so a module
    # with more functions than the cap was not fully scanned. Unfiltered, every
    # function matches, so total is the structural count and scan_capped means it
    # ran past the cap. Filtered, total is the matches actually seen, and
    # scan_capped also fires when functions past the cap could not be examined.
    structural_total = imported_total + defined_total
    not_all_scanned = (len(imported) + len(defined_indices)) < structural_total
    if needle is None:
        total = structural_total
        scan_capped = structural_total > len(functions)
    else:
        total = matched
        scan_capped = emission_capped or not_all_scanned

    result: JsonObject = {
        "functions": functions,
        "count": len(functions),
        "total": total,
        "imported_count": imported_total,
        "defined_count": defined_total,
        "scan_capped": scan_capped,
    }
    if needle is not None:
        result["filtered"] = True
        result["query"] = contains
    return result


def list_wasm_functions(path: Path, *, contains: str | None = None) -> JsonObject:
    """List the functions of the module at ``path`` (applies the shared 16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return list_wasm_functions_bytes(data, contains=contains)


def _resolve_func_signature(
    global_index: int,
    imported_type_indices: list[int],
    imported_func_total: int,
    defined_indices: list[int],
    types: list[tuple[list[str], list[str]] | None],
) -> tuple[str, int | None, list[str], list[str], bool]:
    """Map a global function index to (origin, type_index, params, results, unknown).

    Imported functions occupy the low index space ``[0, imported_func_total)``;
    the module's own functions follow. ``origin`` is "imported" or "defined".
    The type index (and thus the signature) is unresolvable -- reported by the
    trailing bool -- when the index falls past the section that would carry it
    (a count beyond the parser's cap, or a truncated section), or when the type
    entry itself is a GC form the type parser stopped at.
    """
    if global_index < imported_func_total:
        origin = "imported"
        type_index = (
            imported_type_indices[global_index]
            if 0 <= global_index < len(imported_type_indices)
            else None
        )
    else:
        origin = "defined"
        offset = global_index - imported_func_total
        type_index = (
            defined_indices[offset] if 0 <= offset < len(defined_indices) else None
        )
    if type_index is None:
        return origin, None, [], [], True
    signature = types[type_index] if 0 <= type_index < len(types) else None
    if signature is None:
        return origin, type_index, [], [], True
    return origin, type_index, list(signature[0]), list(signature[1]), False


def list_wasm_exports_bytes(data: bytes, *, contains: str | None = None) -> JsonObject:
    """List a module's exports -- its callable/public surface -- with signatures.

    The export section is the module's public API: the names JS reaches through
    ``instance.exports``. wasm.summary lists them coarsely (name/kind/index) and
    wasm.functions lists every function but not which ones are exported; neither
    resolves an exported function's signature. This joins the export section to
    the type/import/function sections so a function export comes back with its
    resolved params/results -- the exact ABI a caller invokes -- and, from the
    ``name`` custom section, the internal name behind the export name.

    Each entry carries name (the exported name), kind (func/table/memory/global)
    and index (the index into that kind's space). For a func export it also
    carries origin (imported/defined -- a re-exported host import versus a
    module function), type_index, params and results (value-type names), the
    internal_name when the name section has one, and signature_unknown when the
    type cannot be resolved. Also count, total and scan_capped (more exports
    exist than were listed). Only the type/import/function/export/name sections
    are read; every other section is skipped by its declared length. Bad magic
    raises invalid_params.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    needle = contains.casefold() if contains else None
    cursor = _Cursor(data)
    cursor.pos = 8

    types: list[tuple[list[str], list[str]] | None] = []
    imported_type_indices: list[int] = []
    imported_func_total = 0
    defined_indices: list[int] = []
    exports_raw: list[JsonObject] = []
    exports_total = 0
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 1:  # type
            types = _parse_functypes(body)
        elif section_id == 2:  # import
            imported_funcs, imported_func_total = _parse_import_funcs(body)
            imported_type_indices = [type_index for _, _, type_index in imported_funcs]
        elif section_id == 3:  # function
            defined_indices, _ = _parse_function_section(body, _MAX_ITEMS)
        elif section_id == 7:  # export
            exports_raw, exports_total = _parse_exports(body)
        # Every other section is skipped by its declared length.

    # The name section is a bonus join; a corrupt one must not fail the listing.
    names: dict[int, str] = {}
    with contextlib.suppress(JsReError):
        names = _function_name_map(data)

    exports: list[JsonObject] = []
    matched = 0
    emission_capped = False
    for record in exports_raw:
        name = str(record.get("name", ""))
        kind = str(record.get("kind", ""))
        index = int(record.get("index", 0))
        if needle is not None and needle not in f"{name} {kind}".casefold():
            continue
        matched += 1
        if len(exports) >= _MAX_ITEMS:
            emission_capped = True
            continue
        entry: JsonObject = {"name": name, "kind": kind, "index": index}
        if kind == "func":
            origin, type_index, params, results, unknown = _resolve_func_signature(
                index, imported_type_indices, imported_func_total, defined_indices, types
            )
            entry["origin"] = origin
            entry["type_index"] = type_index
            entry["params"] = params
            entry["results"] = results
            if unknown:
                entry["signature_unknown"] = True
            internal = names.get(index)
            if internal is not None:
                entry["internal_name"] = internal
        exports.append(entry)

    # exports_raw is already capped at _MAX_ITEMS by _parse_exports, with the
    # true count in exports_total. Unfiltered, the listing is everything that
    # fit; scan_capped means more existed. Filtered, total is the matches seen
    # in that head, and scan_capped also fires when exports past the cap could
    # not be examined.
    not_all_scanned = exports_total > len(exports_raw)
    if needle is None:
        total = exports_total
        scan_capped = exports_total > len(exports)
    else:
        total = matched
        scan_capped = emission_capped or not_all_scanned

    result: JsonObject = {
        "exports": exports,
        "count": len(exports),
        "total": total,
        "scan_capped": scan_capped,
    }
    if needle is not None:
        result["filtered"] = True
        result["query"] = contains
    return result


def list_wasm_exports(path: Path, *, contains: str | None = None) -> JsonObject:
    """List the exports of the module at ``path`` (applies the shared 16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return list_wasm_exports_bytes(data, contains=contains)


def _read_import_limits(cursor: _Cursor) -> JsonObject:
    """A limits record for an import, keeping the shared-memory flag visible.

    Same wire format as ``_read_limits`` (flags, minimum, maximum when bit 0 is
    set), but bit 1 -- the threads proposal's shared-memory marker -- is
    surfaced as ``shared`` because an imported shared memory is a real signal
    (the module expects a SharedArrayBuffer-backed memory).
    """
    flags = cursor.byte()
    limits: JsonObject = {"initial": cursor.uleb()}
    if flags & 0x01:
        limits["maximum"] = cursor.uleb()
    if flags & 0x02:
        limits["shared"] = True
    return limits


def _parse_imports_described(body: _Cursor) -> tuple[list[JsonObject], int, dict[str, int]]:
    """Import section (id 2) with every import's descriptor fully decoded.

    Returns (collected, total, per-kind totals). Unlike ``_parse_imports`` (which
    only names each import) and ``_parse_import_funcs`` (which keeps only the
    functions), this decodes each kind's descriptor tail into fields: a func's
    type index, a table's reftype and limits, a memory's limits (with the shared
    flag), a global's value type and mutability. ``index`` is the slot the import
    occupies in its kind's own index space -- imports fill the low indices, so a
    func import's index is its global function index. Collection is capped at
    ``_MAX_ITEMS`` but the whole section is still walked, so the per-kind totals
    are exact and a malformed descriptor past the cap still raises.
    """
    total = body.uleb()
    collected: list[JsonObject] = []
    kind_totals = {"func": 0, "table": 0, "memory": 0, "global": 0}
    for index in range(total):
        module = body.name()
        field = body.name()
        kind_byte = body.byte()
        record: JsonObject = {"module": module, "name": field}
        if kind_byte == 0:
            record["kind"] = "func"
            record["index"] = kind_totals["func"]
            record["type_index"] = body.uleb()
            kind_totals["func"] += 1
        elif kind_byte == 1:
            record["kind"] = "table"
            record["index"] = kind_totals["table"]
            reftype = body.byte()
            record["reftype"] = _VALTYPE.get(reftype, f"type 0x{reftype:02x}")
            record.update(_read_import_limits(body))
            kind_totals["table"] += 1
        elif kind_byte == 2:
            record["kind"] = "memory"
            record["index"] = kind_totals["memory"]
            record.update(_read_import_limits(body))
            kind_totals["memory"] += 1
        elif kind_byte == 3:
            record["kind"] = "global"
            record["index"] = kind_totals["global"]
            record["valtype"] = _valtype(body)
            record["mutable"] = bool(body.byte() & 0x01)
            kind_totals["global"] += 1
        else:
            raise JsReError("invalid_params", "wasm import has an unknown external kind")
        if index < _MAX_ITEMS:
            collected.append(record)
    return collected, total, kind_totals


# The distinct source modules are a small identity list ("env" vs
# "wasi_snapshot_preview1" tells the runtime story in one line), kept apart
# from the 4096 import cap so it stays readable.
_MAX_IMPORT_MODULES = 64


def list_wasm_imports_bytes(data: bytes, *, contains: str | None = None) -> JsonObject:
    """List a module's imports -- what it requires from the host -- decoded.

    The import section is the module's host boundary: every function, memory,
    table and global it cannot run without. wasm.summary names imports coarsely
    (module/name/kind) and wasm.functions resolves only the imported functions;
    neither decodes the non-func descriptors. This decodes all four kinds: a
    func import's resolved params/results (joined through the type section), a
    memory import's page limits and shared flag, a table import's reftype and
    limits, a global import's value type and mutability. It is the mirror of
    wasm.exports (what the module provides) and reads like a native binary's
    import table.

    Each entry carries module (the host-side namespace, e.g. env or
    wasi_snapshot_preview1), name, kind, and index (the slot in that kind's
    index space -- imports fill the low indices, so a func import's index is
    its global function index). A func entry adds type_index, params and
    results (signature_unknown when unresolvable); a table entry reftype plus
    initial/maximum; a memory entry initial/maximum in 64 KiB pages plus shared
    when the threads flag is set; a global entry valtype and mutable. Also
    count, total, scan_capped, per-kind func_count/table_count/memory_count/
    global_count (exact even past the cap), and the distinct source modules as
    modules/module_count. Only the type/import sections are read; every other
    section is skipped by its declared length. Bad magic raises invalid_params.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    needle = contains.casefold() if contains else None
    cursor = _Cursor(data)
    cursor.pos = 8

    types: list[tuple[list[str], list[str]] | None] = []
    imports_raw: list[JsonObject] = []
    imports_total = 0
    kind_totals = {"func": 0, "table": 0, "memory": 0, "global": 0}
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 1:  # type
            types = _parse_functypes(body)
        elif section_id == 2:  # import
            imports_raw, imports_total, kind_totals = _parse_imports_described(body)
        # Every other section is skipped by its declared length.

    imports: list[JsonObject] = []
    modules: set[str] = set()
    matched = 0
    emission_capped = False
    for record in imports_raw:
        module = str(record.get("module", ""))
        name = str(record.get("name", ""))
        kind = str(record.get("kind", ""))
        modules.add(module)
        if needle is not None and needle not in f"{module} {name} {kind}".casefold():
            continue
        matched += 1
        if len(imports) >= _MAX_ITEMS:
            emission_capped = True
            continue
        entry = dict(record)
        if kind == "func":
            type_index = int(entry.get("type_index", -1))
            signature = types[type_index] if 0 <= type_index < len(types) else None
            if signature is None:
                entry["params"] = []
                entry["results"] = []
                entry["signature_unknown"] = True
            else:
                entry["params"] = list(signature[0])
                entry["results"] = list(signature[1])
        imports.append(entry)

    # imports_raw is already capped at _MAX_ITEMS by the parser, with the true
    # count in imports_total. Unfiltered, total is the structural count and
    # scan_capped means more existed than were listed. Filtered, total is the
    # matches seen in the scanned head, and scan_capped also fires when imports
    # past the cap could not be examined.
    not_all_scanned = imports_total > len(imports_raw)
    if needle is None:
        total = imports_total
        scan_capped = imports_total > len(imports)
    else:
        total = matched
        scan_capped = emission_capped or not_all_scanned

    result: JsonObject = {
        "imports": imports,
        "count": len(imports),
        "total": total,
        "scan_capped": scan_capped,
        "func_count": kind_totals["func"],
        "table_count": kind_totals["table"],
        "memory_count": kind_totals["memory"],
        "global_count": kind_totals["global"],
        "modules": sorted(modules)[:_MAX_IMPORT_MODULES],
        "module_count": len(modules),
    }
    if needle is not None:
        result["filtered"] = True
        result["query"] = contains
    return result


def list_wasm_imports(path: Path, *, contains: str | None = None) -> JsonObject:
    """List the imports of the module at ``path`` (applies the shared 16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return list_wasm_imports_bytes(data, contains=contains)


def _read_global_init(cursor: _Cursor) -> JsonObject:
    """Decode a global's init constant-expression into a compact description.

    A global's initializer is a constant expr terminated by ``end`` (0x0B): in
    practice a single numeric const (i32/i64 as SLEB, f32/f64 as raw IEEE bytes)
    or ``global.get N`` referencing an imported global (how a linker seeds a
    heap-base from the host). The literal is lifted so a reader sees the actual
    seed value -- a stack pointer's ``i32.const 0x100000`` or a feature flag's
    ``i32.const 1``. Anything unexpected is read to the end marker so the cursor
    stays aligned, and reported as the bare op. The body is sliced, so a
    malformed expr raises invalid_params rather than reading past the section.
    """
    opcode = cursor.byte()
    init: JsonObject
    if opcode == 0x41:  # i32.const
        init = {"op": "i32.const", "value": cursor.sleb()}
    elif opcode == 0x42:  # i64.const
        init = {"op": "i64.const", "value": cursor.sleb()}
    elif opcode == 0x43:  # f32.const -- four raw little-endian bytes, not LEB
        init = {"op": "f32.const", "value": struct.unpack("<f", cursor.take(4))[0]}
    elif opcode == 0x44:  # f64.const -- eight raw little-endian bytes
        init = {"op": "f64.const", "value": struct.unpack("<d", cursor.take(8))[0]}
    elif opcode == 0x23:  # global.get
        init = {"op": "global.get", "global": cursor.uleb()}
    elif opcode == 0x0B:  # empty expr (defensive: invalid, but do not crash)
        return {"op": "empty"}
    else:
        init = {"op": "expr"}
    end = cursor.byte()
    if end != 0x0B:
        # A multi-instruction or unsupported expr: read to the end marker so the
        # next global's type byte is where the cursor lands.
        while cursor.byte() != 0x0B:
            pass
    return init


def _init_str(init: JsonObject) -> str:
    """A global init's one-line form: ``i32.const 1024`` / ``global.get 0`` / op."""
    op = str(init["op"])
    if "value" in init:
        return f"{op} {init['value']}"
    if "global" in init:
        return f"{op} {init['global']}"
    return op


def _parse_global_section(body: _Cursor, imported_globals: int) -> tuple[list[JsonObject], int]:
    """Global section (id 6): (collected defined globals, total defined).

    Each entry is a globaltype (value type byte + mutability byte) followed by an
    init const-expr. ``index`` is the global index in the whole global index
    space -- imported globals occupy the low indices, so a defined global's index
    is ``imported_globals + position``, matching how wasm.imports numbers them.
    Collection is capped at ``_MAX_ITEMS`` but every entry is still consumed so a
    lying count runs out of the bounded body and raises rather than truncating.
    """
    total = body.uleb()
    out: list[JsonObject] = []
    for position in range(total):
        valtype = _valtype(body)
        mutable = bool(body.byte() & 0x01)
        init = _read_global_init(body)
        if position < _MAX_ITEMS:
            entry: JsonObject = {
                "index": imported_globals + position,
                "valtype": valtype,
                "mutable": mutable,
                "init": _init_str(init),
            }
            if "value" in init:
                entry["init_value"] = init["value"]
            if "global" in init:
                entry["init_global"] = init["global"]
            out.append(entry)
    return out, total


def list_wasm_globals_bytes(data: bytes) -> JsonObject:
    """List a module's defined globals -- its mutable state and seed constants.

    wasm.imports decodes imported globals and wasm.exports only names exported
    ones; neither lists the module's own globals (section 6) with the init value
    they start at. Those globals are where a linker keeps the shadow stack
    pointer, the heap base and feature flags, so the seed constant is the datum
    an analyst wants. This reads the global section directly (pure Python, no
    wabt), decoding each global's value type, mutability and constant
    initializer.

    Each entry carries index (the global index, imported globals first), valtype
    (i32/i64/f32/f64/v128/funcref/externref), mutable (a var vs a const global),
    and init (the initializer's one-line form, e.g. "i32.const 1048576" or
    "global.get 0"); a numeric const also carries init_value and a global.get
    carries init_global. Also count, total, imported_count (imported globals,
    for the index space) and scan_capped (more globals than the 4096 listed).
    Only the import and global sections are read; every other section is skipped
    by its declared length. Bad magic raises invalid_params.
    """
    if len(data) < 8 or data[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module: bad magic")
    cursor = _Cursor(data)
    cursor.pos = 8

    imported_globals = 0
    globals_out: list[JsonObject] = []
    globals_total = 0
    while not cursor.eof:
        section_id = cursor.byte()
        section_len = cursor.uleb()
        body = _Cursor(cursor.take(section_len))
        if section_id == 2:  # import -- count imported globals for the index space
            _, _, kind_totals = _parse_imports_described(body)
            imported_globals = kind_totals["global"]
        elif section_id == 6:  # global
            globals_out, globals_total = _parse_global_section(body, imported_globals)
        # Every other section is skipped by its declared length.

    return {
        "globals": globals_out,
        "count": len(globals_out),
        "total": globals_total,
        "imported_count": imported_globals,
        "scan_capped": globals_total > len(globals_out),
    }


def list_wasm_globals(path: Path) -> JsonObject:
    """List the globals of the module at ``path`` (applies the shared 16 MiB cap)."""
    resolved = _require_existing_file(path, missing="wasm file not found")
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"wasm unreadable: {exc}", path=str(resolved)) from exc
    return list_wasm_globals_bytes(data)
