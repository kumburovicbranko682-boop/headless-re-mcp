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
