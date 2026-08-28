"""Pure-stdlib structural reader for a WebAssembly binary module.

wasm.info / wasm.wat drive the wabt CLI (wasm-objdump, wasm2wat), so the whole
WebAssembly inspection surface reports ``capability_unavailable`` on any host
that does not have wabt installed -- the common case on a fresh Linux box. But
the module *structure* an analyst reaches for first (the section layout, what
the module imports from its host, what it exports, which custom sections such as
``name`` or ``producers`` are present) is defined by the binary format itself
and reads with the stdlib alone. summarize_wasm closes that gap: it needs no CLI
and returns machine-readable JSON rather than objdump text, so an agent can
filter and reason over it.

The section walk (a byte id plus a LEB128 size) is simple and reliable; the
per-entry parsing of the import and export vectors is where a malformed or
truncated module bites, so each section is parsed defensively -- a section that
does not decode is recorded with a warning and the walk resumes at its known end
rather than sinking the whole summary. Every list is bounded.
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

_WASM_MAGIC = b"\x00asm"
# Header is magic (4) + version (u32 LE); a module shorter than this has none.
_HEADER = 8

# Section ids per the core spec. Anything outside this maps to unknown(<id>).
_SECTION_NAMES: dict[int, str] = {
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
# Section id -> the counts key its leading LEB128 vector length feeds.
_VEC_COUNT_KEYS: dict[int, str] = {
    1: "types",
    2: "imports",
    3: "functions",
    4: "tables",
    5: "memories",
    6: "globals",
    7: "exports",
    9: "elements",
    11: "data",
}
_IMPORT_EXPORT_KINDS: dict[int, str] = {0: "func", 1: "table", 2: "memory", 3: "global"}

# A summarised entry field, and the number of entries listed, are bounded so a
# module with pathological names or a huge import table cannot inflate a reply.
_MAX_NAME = 4096
_MAX_LISTED = 1024
_MAX_WARNINGS = 32


class WasmParseError(ValueError):
    """Bytes that are not a WebAssembly module.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name. Raised only for the
    header; a section that will not decode is a warning, not a failure.
    """


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 at ``pos``; return (value, next_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise WasmParseError("truncated LEB128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise WasmParseError("LEB128 integer too long")


def _name(data: bytes, pos: int) -> tuple[str, int]:
    """Decode a WASM name (LEB128 length + UTF-8 bytes), bounded on output."""
    length, pos = _uleb(data, pos)
    if length < 0 or pos + length > len(data):
        raise WasmParseError("name overruns the section")
    raw = data[pos : pos + length]
    text = raw.decode("utf-8", errors="replace")
    return text[:_MAX_NAME], pos + length


def _skip_limits(data: bytes, pos: int) -> int:
    """Advance past a limits record (flag, min, and max when the flag says so).

    Bit 0 of the flag means "has max" across the MVP, threads (shared) and
    memory64 encodings, so reading min and then max iff that bit is set skips
    all of them without needing to model which one this is.
    """
    if pos >= len(data):
        raise WasmParseError("truncated limits")
    flag = data[pos]
    pos += 1
    _, pos = _uleb(data, pos)
    if flag & 0x01:
        _, pos = _uleb(data, pos)
    return pos


def _parse_imports(payload: bytes) -> tuple[list[JsonObject], int]:
    """Every import (module, name, kind) and the declared count.

    Descriptors are skipped by kind so the cursor lands on the next entry:
    a func import carries a typeidx, a table a reftype byte plus limits, a
    memory just limits, and a global a valtype byte plus a mutability byte.
    """
    count, pos = _uleb(payload, 0)
    imports: list[JsonObject] = []
    for _ in range(count):
        module, pos = _name(payload, pos)
        field, pos = _name(payload, pos)
        if pos >= len(payload):
            raise WasmParseError("truncated import descriptor")
        kind_byte = payload[pos]
        pos += 1
        if kind_byte == 0:
            _, pos = _uleb(payload, pos)
        elif kind_byte == 1:
            pos += 1  # reftype
            pos = _skip_limits(payload, pos)
        elif kind_byte == 2:
            pos = _skip_limits(payload, pos)
        elif kind_byte == 3:
            pos += 2  # valtype + mutability
        else:
            raise WasmParseError(f"unknown import kind {kind_byte}")
        if len(imports) < _MAX_LISTED:
            imports.append(
                {
                    "module": module,
                    "name": field,
                    "kind": _IMPORT_EXPORT_KINDS.get(kind_byte, f"unknown({kind_byte})"),
                }
            )
    return imports, count


def _parse_exports(payload: bytes) -> tuple[list[JsonObject], int]:
    """Every export (name, kind, index) and the declared count."""
    count, pos = _uleb(payload, 0)
    exports: list[JsonObject] = []
    for _ in range(count):
        name, pos = _name(payload, pos)
        if pos >= len(payload):
            raise WasmParseError("truncated export descriptor")
        kind_byte = payload[pos]
        pos += 1
        index, pos = _uleb(payload, pos)
        if len(exports) < _MAX_LISTED:
            exports.append(
                {
                    "name": name,
                    "kind": _IMPORT_EXPORT_KINDS.get(kind_byte, f"unknown({kind_byte})"),
                    "index": index,
                }
            )
    return exports, count


def summarize_wasm(data: bytes) -> JsonObject:
    """Structural summary of a WebAssembly module, stdlib only.

    Raises WasmParseError when the header is not a WebAssembly module. Beyond
    that the walk is resilient: a section whose body will not decode contributes
    a warning and its framing (id, size) still advances the cursor, so a summary
    of a slightly-off module still reports every section it could read.
    """
    if len(data) < _HEADER or data[:4] != _WASM_MAGIC:
        raise WasmParseError("not a WebAssembly module: missing the \\0asm magic")
    version = int.from_bytes(data[4:8], "little")

    sections: list[JsonObject] = []
    counts: dict[str, int] = {}
    imports: list[JsonObject] = []
    imports_total = 0
    imports_truncated = False
    exports: list[JsonObject] = []
    exports_total = 0
    exports_truncated = False
    custom_sections: list[str] = []
    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    pos = _HEADER
    while pos < len(data):
        section_id = data[pos]
        pos += 1
        try:
            size, pos = _uleb(data, pos)
        except WasmParseError:
            warn("truncated section size; stopped")
            break
        payload_end = pos + size
        if size < 0 or payload_end > len(data):
            warn(f"section {section_id} overruns the file; stopped")
            break
        payload = data[pos:payload_end]
        entry: JsonObject = {
            "id": section_id,
            "name": _SECTION_NAMES.get(section_id, f"unknown({section_id})"),
            "size": size,
        }
        if section_id == 0:
            try:
                custom_name, _ = _name(payload, 0)
                entry["custom_name"] = custom_name
                if len(custom_sections) < _MAX_LISTED:
                    custom_sections.append(custom_name)
            except WasmParseError:
                warn("custom section has no readable name")
            counts["custom"] = counts.get("custom", 0) + 1
        else:
            vec_key = _VEC_COUNT_KEYS.get(section_id)
            if vec_key is not None:
                try:
                    vec_count, _ = _uleb(payload, 0)
                    counts[vec_key] = vec_count
                except WasmParseError:
                    warn(f"{entry['name']} section: unreadable vector count")
            if section_id == 2:
                try:
                    imports, imports_total = _parse_imports(payload)
                    imports_truncated = imports_total > len(imports)
                except WasmParseError as exc:
                    warn(f"import section: {exc}")
            elif section_id == 7:
                try:
                    exports, exports_total = _parse_exports(payload)
                    exports_truncated = exports_total > len(exports)
                except WasmParseError as exc:
                    warn(f"export section: {exc}")
        sections.append(entry)
        pos = payload_end

    return {
        "version": version,
        "size": len(data),
        "sections": sections,
        "counts": counts,
        "imports": imports,
        "imports_total": imports_total,
        "imports_truncated": imports_truncated,
        "exports": exports,
        "exports_total": exports_total,
        "exports_truncated": exports_truncated,
        "custom_sections": custom_sections,
        "has_names_section": "name" in custom_sections,
        "warnings": warnings,
    }
