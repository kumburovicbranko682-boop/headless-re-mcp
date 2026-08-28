"""Pure-Python summary of a WebAssembly module's structure.

Unlike ``wasm.wat`` / ``wasm.info`` (which shell out to wabt's ``wasm2wat`` and
``wasm-objdump``), this reads the binary section table directly, so it answers
even on a host where wabt was never installed. It does not disassemble code;
it lays out the sections, folds the import/export surface -- the single most
useful thing for triaging a stripped module, since it names the host functions
the module reaches for (``wasi_snapshot_preview1.*``, ``env.emscripten_*``) --
and reports memory limits, the start function, and the custom-section list.

Every walk is bounded by the section's declared payload size, so one malformed
section is recorded and skipped rather than derailing the whole summary, and a
binary that ends mid-section comes back with ``truncated`` set instead of an
exception.
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

_WASM_MAGIC = b"\x00asm"

# Section ids per the core spec. Anything outside this map is reported by id
# with name "unknown" rather than dropped, so a newer proposal's section still
# shows up in the table.
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

# import/export descriptor kinds share the same 0..3 encoding.
_EXTERN_KINDS: dict[int, str] = {0: "func", 1: "table", 2: "memory", 3: "global"}

# Common value types, for a readable global/param rendering. Unknown bytes are
# rendered as "0x.." rather than guessed.
_VALTYPES: dict[int, str] = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}

# A real emscripten module carries a few hundred imports and exports; a hostile
# or generated one could carry far more. Both lists (and the custom-section
# roll-up) are capped, and each cut is announced with a *_truncated flag so a
# reader never mistakes a capped list for the whole surface.
_MAX_SECTIONS = 256
_MAX_IMPORTS = 500
_MAX_EXPORTS = 500
_MAX_MEMORIES = 64
_MAX_CUSTOM = 128
_MAX_NAME_CHARS = 512


class _WasmTruncated(Exception):
    """The declared structure ran past the end of the available bytes."""


class _WasmMalformed(Exception):
    """A field was encoded in a way the spec does not permit."""


def _u8(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise _WasmTruncated
    return data[pos], pos + 1


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one LEB128 unsigned integer, guarding against a runaway encoding."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _WasmTruncated
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
        # 64-bit is the widest index/size the format uses; a longer run is a
        # corrupt or adversarial encoding, not a value we should keep shifting.
        if shift > 63:
            raise _WasmMalformed


def _name(data: bytes, pos: int) -> tuple[str, int]:
    """Read a WASM name: a uleb length followed by that many UTF-8 bytes."""
    length, pos = _uleb(data, pos)
    end = pos + length
    if end > len(data):
        raise _WasmTruncated
    text = data[pos:end].decode("utf-8", errors="replace")
    return text[:_MAX_NAME_CHARS], end


def _valtype(byte: int) -> str:
    return _VALTYPES.get(byte, f"0x{byte:02x}")


def _limits(data: bytes, pos: int) -> tuple[dict[str, Any], int]:
    """Decode a limits record (flags, min, optional max, shared bit)."""
    flags, pos = _uleb(data, pos)
    minimum, pos = _uleb(data, pos)
    has_max = bool(flags & 0x1)
    maximum: int | None = None
    if has_max:
        maximum, pos = _uleb(data, pos)
    return (
        {"initial": minimum, "maximum": maximum, "shared": bool(flags & 0x2)},
        pos,
    )


def _parse_imports(payload: bytes) -> tuple[list[JsonObject], dict[str, int], bool]:
    """Fold the import section into a bounded list and a per-kind tally."""
    count, pos = _uleb(payload, 0)
    kinds = {"func": 0, "table": 0, "memory": 0, "global": 0}
    items: list[JsonObject] = []
    truncated = False
    for _ in range(count):
        module, pos = _name(payload, pos)
        field, pos = _name(payload, pos)
        kind_byte, pos = _u8(payload, pos)
        kind = _EXTERN_KINDS.get(kind_byte, f"0x{kind_byte:02x}")
        detail: JsonObject = {"module": module, "name": field, "kind": kind}
        if kind_byte == 0:  # func: type index
            type_index, pos = _uleb(payload, pos)
            detail["type_index"] = type_index
        elif kind_byte == 1:  # table: reftype + limits
            reftype, pos = _u8(payload, pos)
            detail["element_type"] = _valtype(reftype)
            limits, pos = _limits(payload, pos)
            detail["limits"] = limits
        elif kind_byte == 2:  # memory: limits
            limits, pos = _limits(payload, pos)
            detail["limits"] = limits
        elif kind_byte == 3:  # global: valtype + mutability
            valtype, pos = _u8(payload, pos)
            mutable, pos = _u8(payload, pos)
            detail["value_type"] = _valtype(valtype)
            detail["mutable"] = bool(mutable)
        else:
            # Unknown extern kind: we cannot know its descriptor length, so we
            # stop here rather than desync the offset for the rest of the list.
            if kind in kinds:
                kinds[kind] += 1
            if len(items) < _MAX_IMPORTS:
                items.append(detail)
            truncated = truncated or len(items) >= _MAX_IMPORTS
            break
        if kind in kinds:
            kinds[kind] += 1
        if len(items) < _MAX_IMPORTS:
            items.append(detail)
        else:
            truncated = True
    return items, kinds, truncated


def _parse_exports(payload: bytes) -> tuple[list[JsonObject], dict[str, int], bool]:
    """Fold the export section into a bounded list and a per-kind tally."""
    count, pos = _uleb(payload, 0)
    kinds = {"func": 0, "table": 0, "memory": 0, "global": 0}
    items: list[JsonObject] = []
    truncated = False
    for _ in range(count):
        field, pos = _name(payload, pos)
        kind_byte, pos = _u8(payload, pos)
        index, pos = _uleb(payload, pos)
        kind = _EXTERN_KINDS.get(kind_byte, f"0x{kind_byte:02x}")
        if kind in kinds:
            kinds[kind] += 1
        if len(items) < _MAX_EXPORTS:
            items.append({"name": field, "kind": kind, "index": index})
        else:
            truncated = True
    return items, kinds, truncated


def _parse_memories(payload: bytes) -> tuple[list[JsonObject], int, bool]:
    """Decode the memory section (a vector of limits records)."""
    count, pos = _uleb(payload, 0)
    memories: list[JsonObject] = []
    truncated = False
    for _ in range(count):
        limits, pos = _limits(payload, pos)
        if len(memories) < _MAX_MEMORIES:
            memories.append(
                {
                    "initial_pages": limits["initial"],
                    "max_pages": limits["maximum"],
                    "shared": limits["shared"],
                }
            )
        else:
            truncated = True
    return memories, count, truncated


def _module_name(payload: bytes) -> str | None:
    """Read subsection 0 (module name) from a ``name`` custom section, if present."""
    pos = 0
    while pos < len(payload):
        sub_id, pos = _u8(payload, pos)
        size, pos = _uleb(payload, pos)
        end = pos + size
        if end > len(payload):
            raise _WasmTruncated
        if sub_id == 0:  # module name subsection
            name, _ = _name(payload, pos)
            return name
        pos = end
    return None


def _leading_count(payload: bytes) -> int | None:
    """The vector length that opens most sections, or None if it cannot be read."""
    try:
        count, _ = _uleb(payload, 0)
    except (_WasmTruncated, _WasmMalformed):
        return None
    return count


def summarize_wasm(data: bytes) -> JsonObject:
    """Summarize a WebAssembly module from its raw bytes.

    The caller is expected to have size-bounded ``data`` already. This never
    raises on malformed input: a bad section is recorded in
    ``malformed_sections`` and skipped, and a binary that ends early sets
    ``truncated``.
    """
    result: JsonObject = {
        "version": None,
        "bytes": len(data),
        "section_count": 0,
        "sections": [],
        "sections_truncated": False,
        "type_count": 0,
        "import_count": 0,
        "function_count": 0,
        "table_count": 0,
        "memory_count": 0,
        "global_count": 0,
        "export_count": 0,
        "element_count": 0,
        "data_segment_count": 0,
        "start_function": None,
        "imports": [],
        "import_kinds": {"func": 0, "table": 0, "memory": 0, "global": 0},
        "imports_truncated": False,
        "exports": [],
        "export_kinds": {"func": 0, "table": 0, "memory": 0, "global": 0},
        "exports_truncated": False,
        "memories": [],
        "custom_sections": [],
        "custom_sections_truncated": False,
        "has_name_section": False,
        "module_name": None,
        "truncated": False,
        "malformed_sections": [],
    }

    if data[:4] != _WASM_MAGIC:
        result["malformed_sections"].append("magic")
        return result
    if len(data) < 8:
        result["truncated"] = True
        return result
    result["version"] = int.from_bytes(data[4:8], "little")

    pos = 8
    sections: list[JsonObject] = []
    custom_names: list[str] = []
    while pos < len(data):
        try:
            section_id, pos = _u8(data, pos)
            size, size_end = _uleb(data, pos)
        except (_WasmTruncated, _WasmMalformed):
            result["truncated"] = True
            break
        payload_start = size_end
        payload_end = payload_start + size
        if payload_end > len(data):
            # Declared size runs past EOF: record what we know and stop.
            result["truncated"] = True
            if len(sections) < _MAX_SECTIONS:
                sections.append(
                    {
                        "id": section_id,
                        "name": _SECTION_NAMES.get(section_id, "unknown"),
                        "size": size,
                        "offset": payload_start,
                        "count": None,
                    }
                )
            break
        payload = data[payload_start:payload_end]
        pos = payload_end

        name = _SECTION_NAMES.get(section_id, "unknown")
        entry: JsonObject = {
            "id": section_id,
            "name": name,
            "size": size,
            "offset": payload_start,
            "count": None,
        }

        try:
            if section_id == 0:  # custom
                cname, after_name = _name(payload, 0)
                entry["custom_name"] = cname
                if len(custom_names) < _MAX_CUSTOM:
                    custom_names.append(cname)
                else:
                    result["custom_sections_truncated"] = True
                if cname == "name":
                    result["has_name_section"] = True
                    result["module_name"] = _module_name(payload[after_name:])
            elif section_id == 1:  # type
                result["type_count"] = _leading_count(payload) or 0
                entry["count"] = result["type_count"]
            elif section_id == 2:  # import
                items, kinds, cut = _parse_imports(payload)
                result["imports"] = items
                result["import_kinds"] = kinds
                result["imports_truncated"] = cut
                result["import_count"] = sum(kinds.values())
                entry["count"] = result["import_count"]
            elif section_id == 3:  # function
                result["function_count"] = _leading_count(payload) or 0
                entry["count"] = result["function_count"]
            elif section_id == 4:  # table
                result["table_count"] = _leading_count(payload) or 0
                entry["count"] = result["table_count"]
            elif section_id == 5:  # memory
                memories, count, cut = _parse_memories(payload)
                result["memories"] = memories
                result["memory_count"] = count
                result["memories_truncated"] = cut
                entry["count"] = count
            elif section_id == 6:  # global
                result["global_count"] = _leading_count(payload) or 0
                entry["count"] = result["global_count"]
            elif section_id == 7:  # export
                items, kinds, cut = _parse_exports(payload)
                result["exports"] = items
                result["export_kinds"] = kinds
                result["exports_truncated"] = cut
                result["export_count"] = sum(kinds.values())
                entry["count"] = result["export_count"]
            elif section_id == 8:  # start
                start_index, _ = _uleb(payload, 0)
                result["start_function"] = start_index
            elif section_id == 9:  # element
                result["element_count"] = _leading_count(payload) or 0
                entry["count"] = result["element_count"]
            elif section_id == 11:  # data
                result["data_segment_count"] = _leading_count(payload) or 0
                entry["count"] = result["data_segment_count"]
            elif section_id == 12:  # data count
                declared, _ = _uleb(payload, 0)
                entry["count"] = declared
        except (_WasmTruncated, _WasmMalformed):
            result["malformed_sections"].append(name)

        if len(sections) < _MAX_SECTIONS:
            sections.append(entry)
        else:
            result["sections_truncated"] = True

    result["sections"] = sections
    result["section_count"] = len(sections)
    result["custom_sections"] = custom_names
    return result
