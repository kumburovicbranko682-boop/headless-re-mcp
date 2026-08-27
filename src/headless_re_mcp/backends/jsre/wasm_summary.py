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

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.jsre.client import JsReError, _require_existing_file

JsonObject = dict[str, Any]

_WASM_MAGIC = b"\x00asm"
# func/table/memory/global -- the four external kinds an import or export can
# name. Anything else means the module is malformed or from a newer proposal we
# do not claim to understand, so it is reported verbatim as "kind <n>".
_EXTERNAL_KIND = {0: "func", 1: "table", 2: "memory", 3: "global"}
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
