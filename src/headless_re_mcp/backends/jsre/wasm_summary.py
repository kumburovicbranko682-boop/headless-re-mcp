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

# wasm.strings caps: a data section can hold megabytes of blob, so the printable
# run list is capped and each run is length-limited, exactly like the wabt-free
# summary caps above.
_MAX_STRINGS = 4096
_MAX_STRING_CHARS = 2048


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


def _sleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one LEB128 signed integer (used inside i32/i64.const offsets)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _WasmTruncated
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            if shift < 64 and (byte & 0x40):
                result |= -(1 << shift)
            return result, pos
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


def _skip_const_expr(data: bytes, pos: int) -> int:
    """Advance past a constant init expression, up to and including its end (0x0b).

    Data-segment offsets are constant expressions; we do not evaluate them, we
    only need to step over them to reach the bytes. An opcode we do not model
    is a malformed (to us) expression -- raising rather than guessing keeps the
    offset from desyncing the rest of the vector.
    """
    while True:
        op, pos = _u8(data, pos)
        if op == 0x0B:  # end
            return pos
        if op in (0x41, 0x42):  # i32.const / i64.const
            _, pos = _sleb(data, pos)
        elif op == 0x43:  # f32.const
            pos += 4
        elif op == 0x44:  # f64.const
            pos += 8
        elif op == 0x23:  # global.get
            _, pos = _uleb(data, pos)
        elif op == 0xD0:  # ref.null <heaptype>
            _, pos = _u8(data, pos)
        elif op == 0xD2:  # ref.func <funcidx>
            _, pos = _uleb(data, pos)
        else:
            raise _WasmMalformed
        if pos > len(data):
            raise _WasmTruncated


def _data_section_payload(data: bytes) -> bytes | None:
    """Return the raw payload of the data section (id 11), or None if absent."""
    if data[:4] != _WASM_MAGIC or len(data) < 8:
        return None
    pos = 8
    while pos < len(data):
        try:
            section_id, pos = _u8(data, pos)
            size, pos = _uleb(data, pos)
        except (_WasmTruncated, _WasmMalformed):
            return None
        end = pos + size
        if end > len(data):
            return None
        if section_id == 11:
            return data[pos:end]
        pos = end
    return None


def _data_segments(payload: bytes) -> list[tuple[int, bytes]]:
    """Split the data section into (segment_index, raw_bytes) pairs."""
    count, pos = _uleb(payload, 0)
    segments: list[tuple[int, bytes]] = []
    for index in range(count):
        flag, pos = _uleb(payload, pos)
        if flag == 0:  # active, memory 0: offset expr then bytes
            pos = _skip_const_expr(payload, pos)
        elif flag == 1:  # passive: bytes only
            pass
        elif flag == 2:  # active, explicit memory index: memidx, offset, bytes
            _, pos = _uleb(payload, pos)
            pos = _skip_const_expr(payload, pos)
        else:
            raise _WasmMalformed
        length, pos = _uleb(payload, pos)
        end = pos + length
        if end > len(payload):
            raise _WasmTruncated
        segments.append((index, payload[pos:end]))
        pos = end
    return segments


def _printable_runs(blob: bytes, min_length: int) -> list[tuple[int, str]]:
    """Find runs of >= min_length printable ASCII bytes, as classic ``strings`` does."""
    runs: list[tuple[int, str]] = []
    start: int | None = None
    for i, byte in enumerate(blob):
        printable = 0x20 <= byte <= 0x7E or byte == 0x09
        if printable:
            if start is None:
                start = i
        elif start is not None:
            if i - start >= min_length:
                runs.append((start, blob[start:i].decode("ascii", "replace")))
            start = None
    if start is not None and len(blob) - start >= min_length:
        runs.append((start, blob[start:].decode("ascii", "replace")))
    return runs


def extract_wasm_strings(data: bytes, *, min_length: int = 4) -> JsonObject:
    """Pull printable string constants out of a module's data segments.

    Compiled WebAssembly keeps its string literals -- URLs, error text,
    format strings, sometimes keys -- in the data section, so this is the
    quickest triage of a stripped module. Malformed input never raises: a data
    section that cannot be split is reported as malformed and yields no items.
    """
    result: JsonObject = {
        "items": [],
        "count": 0,
        "items_total": 0,
        "items_limit": _MAX_STRINGS,
        "items_truncated": False,
        "min_length": min_length,
        "data_segment_count": 0,
        "malformed": False,
        "has_data_section": False,
    }
    payload = _data_section_payload(data)
    if payload is None:
        return result
    result["has_data_section"] = True
    try:
        segments = _data_segments(payload)
    except (_WasmTruncated, _WasmMalformed):
        result["malformed"] = True
        return result

    result["data_segment_count"] = len(segments)
    items: list[JsonObject] = []
    total = 0
    truncated = False
    for seg_index, blob in segments:
        for offset, text in _printable_runs(blob, min_length):
            total += 1
            if len(items) < _MAX_STRINGS:
                items.append(
                    {
                        "text": text[:_MAX_STRING_CHARS],
                        "segment": seg_index,
                        "offset": offset,
                        "length": len(text),
                    }
                )
            else:
                truncated = True
    result["items"] = items
    result["count"] = len(items)
    result["items_total"] = total
    result["items_truncated"] = truncated
    return result


# The function index space (imports first, then defined) can run to tens of
# thousands in a real emscripten build; cap the materialised list and page it.
_MAX_FUNCTIONS_COLLECT = 50_000
_MAX_FUNCTIONS_PAGE = 2000


def _collect_sections(data: bytes) -> tuple[dict[int, bytes], bytes | None]:
    """Return {section_id: payload} (first occurrence) and the name section body.

    A single linear walk shared by the function listing: it needs the type,
    import and function sections plus the custom ``name`` section, and reading
    them together keeps the offset logic in one place.
    """
    sections: dict[int, bytes] = {}
    name_payload: bytes | None = None
    if data[:4] != _WASM_MAGIC or len(data) < 8:
        return sections, name_payload
    pos = 8
    while pos < len(data):
        try:
            section_id, pos = _u8(data, pos)
            size, pos = _uleb(data, pos)
        except (_WasmTruncated, _WasmMalformed):
            break
        end = pos + size
        if end > len(data):
            break
        payload = data[pos:end]
        if section_id == 0:
            try:
                cname, after = _name(payload, 0)
                if cname == "name" and name_payload is None:
                    name_payload = payload[after:]
            except (_WasmTruncated, _WasmMalformed):
                pass
        elif section_id not in sections:
            sections[section_id] = payload
        pos = end
    return sections, name_payload


def _parse_types(payload: bytes) -> list[tuple[list[str], list[str]]]:
    """Decode the type section into (params, results) function signatures."""
    count, pos = _uleb(payload, 0)
    types: list[tuple[list[str], list[str]]] = []
    for _ in range(count):
        form, pos = _u8(payload, pos)
        if form != 0x60:
            # A non-func type (GC struct/array, etc.) has a different layout we
            # do not model; stopping keeps later indices from desyncing.
            raise _WasmMalformed
        nparams, pos = _uleb(payload, pos)
        params: list[str] = []
        for _ in range(nparams):
            vt, pos = _u8(payload, pos)
            params.append(_valtype(vt))
        nresults, pos = _uleb(payload, pos)
        results: list[str] = []
        for _ in range(nresults):
            vt, pos = _u8(payload, pos)
            results.append(_valtype(vt))
        types.append((params, results))
    return types


def _parse_func_imports(payload: bytes) -> list[tuple[str, str, int]]:
    """Extract (module, name, type_index) for each function import, in order."""
    count, pos = _uleb(payload, 0)
    funcs: list[tuple[str, str, int]] = []
    for _ in range(count):
        module, pos = _name(payload, pos)
        field, pos = _name(payload, pos)
        kind, pos = _u8(payload, pos)
        if kind == 0:  # func: type index
            type_index, pos = _uleb(payload, pos)
            funcs.append((module, field, type_index))
        elif kind == 1:  # table: reftype + limits
            _, pos = _u8(payload, pos)
            _, pos = _limits(payload, pos)
        elif kind == 2:  # memory: limits
            _, pos = _limits(payload, pos)
        elif kind == 3:  # global: valtype + mutability
            _, pos = _u8(payload, pos)
            _, pos = _u8(payload, pos)
        else:
            break
    return funcs


def _parse_function_section(payload: bytes) -> list[int]:
    """Decode the function section into the type index of each defined function."""
    count, pos = _uleb(payload, 0)
    indices: list[int] = []
    for _ in range(count):
        type_index, pos = _uleb(payload, pos)
        indices.append(type_index)
    return indices


def _parse_function_names(payload: bytes) -> dict[int, str]:
    """Decode subsection 1 (function names) of the name custom section."""
    names: dict[int, str] = {}
    pos = 0
    while pos < len(payload):
        sub_id, pos = _u8(payload, pos)
        size, pos = _uleb(payload, pos)
        end = pos + size
        if end > len(payload):
            raise _WasmTruncated
        if sub_id == 1:  # function name subsection: a namemap
            body = payload[pos:end]
            bpos = 0
            entry_count, bpos = _uleb(body, bpos)
            for _ in range(entry_count):
                index, bpos = _uleb(body, bpos)
                text, bpos = _name(body, bpos)
                names[index] = text
        pos = end
    return names


def _parse_local_names(payload: bytes) -> dict[int, list[tuple[int, str]]]:
    """Decode subsection 2 (local names) of the name custom section.

    An indirect name map: for each function index, a name map of local-variable
    index to name. These are the argument and local names a decompiler shows,
    and are not recovered by the function listing.
    """
    out: dict[int, list[tuple[int, str]]] = {}
    pos = 0
    while pos < len(payload):
        sub_id, pos = _u8(payload, pos)
        size, pos = _uleb(payload, pos)
        end = pos + size
        if end > len(payload):
            raise _WasmTruncated
        if sub_id == 2:  # local name subsection: an indirect namemap
            body = payload[pos:end]
            bpos = 0
            func_count, bpos = _uleb(body, bpos)
            for _ in range(func_count):
                func_index, bpos = _uleb(body, bpos)
                local_count, bpos = _uleb(body, bpos)
                locals_list: list[tuple[int, str]] = []
                for _ in range(local_count):
                    local_index, bpos = _uleb(body, bpos)
                    local_name, bpos = _name(body, bpos)
                    locals_list.append((local_index, local_name))
                out[func_index] = locals_list
        pos = end
    return out


def list_wasm_functions(
    data: bytes, *, offset: int = 0, limit: int = 100
) -> JsonObject:
    """List a module's functions with resolved signatures, imports first.

    Where summary only counts them, this walks the whole function index space:
    each imported function (with its module/name) followed by each defined
    function, resolving every type index to params/results and attaching the
    debug name from the name section when present. Never raises on malformed
    input: a section that will not parse is skipped and the affected fields are
    simply absent (types_resolved goes false when the type section is bad).
    """
    result: JsonObject = {
        "functions": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "imported_count": 0,
        "defined_count": 0,
        "types_resolved": True,
        "scan_capped": False,
    }
    sections, name_payload = _collect_sections(data)

    types: list[tuple[list[str], list[str]]] | None = None
    if 1 in sections:
        try:
            types = _parse_types(sections[1])
        except (_WasmTruncated, _WasmMalformed):
            types = None
            result["types_resolved"] = False

    func_imports: list[tuple[str, str, int]] = []
    if 2 in sections:
        try:
            func_imports = _parse_func_imports(sections[2])
        except (_WasmTruncated, _WasmMalformed):
            func_imports = []

    defined: list[int] = []
    if 3 in sections:
        try:
            defined = _parse_function_section(sections[3])
        except (_WasmTruncated, _WasmMalformed):
            defined = []

    func_names: dict[int, str] = {}
    if name_payload is not None:
        try:
            func_names = _parse_function_names(name_payload)
        except (_WasmTruncated, _WasmMalformed):
            func_names = {}

    def _signature(type_index: int) -> JsonObject:
        if types is not None and 0 <= type_index < len(types):
            params, results = types[type_index]
            return {"params": list(params), "results": list(results)}
        return {}

    functions: list[JsonObject] = []
    index = 0
    capped = False
    for module, field, type_index in func_imports:
        if len(functions) >= _MAX_FUNCTIONS_COLLECT:
            capped = True
            break
        entry: JsonObject = {
            "index": index,
            "kind": "imported",
            "module": module,
            "name": field,
            "type_index": type_index,
        }
        entry.update(_signature(type_index))
        if index in func_names:
            entry["debug_name"] = func_names[index]
        functions.append(entry)
        index += 1
    imported_count = index

    if not capped:
        for type_index in defined:
            if len(functions) >= _MAX_FUNCTIONS_COLLECT:
                capped = True
                break
            entry = {
                "index": index,
                "kind": "defined",
                "type_index": type_index,
            }
            entry.update(_signature(type_index))
            if index in func_names:
                entry["name"] = func_names[index]
            functions.append(entry)
            index += 1

    result["imported_count"] = imported_count
    result["defined_count"] = len(functions) - imported_count
    result["total"] = len(functions)
    result["scan_capped"] = capped

    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_FUNCTIONS_PAGE))
    window = functions[start : start + cap]
    result["functions"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(functions)
    return result


_MAX_GLOBALS_COLLECT = 10_000
_MAX_GLOBALS_PAGE = 2000


def _read_const_init(data: bytes, pos: int) -> tuple[JsonObject, int]:
    """Decode a global's init expression: the leading instruction plus its end.

    Reads the first instruction for display, then defers to _skip_const_expr for
    the authoritative end position so a rare multi-instruction expression still
    leaves the vector aligned. An expression whose first opcode we do not model
    raises, which the caller turns into resolved=false.
    """
    op, after = _u8(data, pos)
    init: JsonObject | None = None
    if op == 0x41:  # i32.const
        value, _ = _sleb(data, after)
        init = {"op": "i32.const", "value": value}
    elif op == 0x42:  # i64.const
        value, _ = _sleb(data, after)
        init = {"op": "i64.const", "value": value}
    elif op == 0x43:  # f32.const
        init = {"op": "f32.const"}
    elif op == 0x44:  # f64.const
        init = {"op": "f64.const"}
    elif op == 0x23:  # global.get
        index, _ = _uleb(data, after)
        init = {"op": "global.get", "index": index}
    elif op == 0xD0:  # ref.null
        init = {"op": "ref.null"}
    elif op == 0xD2:  # ref.func
        index, _ = _uleb(data, after)
        init = {"op": "ref.func", "index": index}
    end_pos = _skip_const_expr(data, pos)
    if init is None:
        init = {"op": "complex"}
    return init, end_pos


def _parse_globals(payload: bytes) -> tuple[list[JsonObject], bool]:
    """Decode the global section (id 6): value type, mutability, init expression."""
    count, pos = _uleb(payload, 0)
    out: list[JsonObject] = []
    capped = False
    for _ in range(count):
        if len(out) >= _MAX_GLOBALS_COLLECT:
            capped = True
            break
        vt, pos = _u8(payload, pos)
        mut, pos = _u8(payload, pos)
        init, pos = _read_const_init(payload, pos)
        out.append(
            {
                "value_type": _valtype(vt),
                "mutable": mut == 0x01,
                "init": init,
            }
        )
    return out, capped


def _count_imported_globals(payload: bytes | None) -> int:
    """How many globals the import section brings in (they precede defined ones)."""
    if payload is None:
        return 0
    try:
        count, pos = _uleb(payload, 0)
        imported = 0
        for _ in range(count):
            _, pos = _name(payload, pos)
            _, pos = _name(payload, pos)
            kind, pos = _u8(payload, pos)
            if kind == 0:
                _, pos = _uleb(payload, pos)
            elif kind == 1:
                _, pos = _u8(payload, pos)
                _, pos = _limits(payload, pos)
            elif kind == 2:
                _, pos = _limits(payload, pos)
            elif kind == 3:
                _, pos = _u8(payload, pos)
                _, pos = _u8(payload, pos)
                imported += 1
            else:
                break
        return imported
    except (_WasmTruncated, _WasmMalformed):
        return 0


def list_wasm_globals(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a module's defined globals (section 6) with type, mutability, init.

    summary only counts them. Each row carries its index in the global index
    space (imported globals come first, so the count is added as an offset),
    value_type, mutable, and init -- the decoded leading instruction of the
    initializer (i32.const/f64.const/global.get/ref.func, with value or index
    where it applies). Never raises: an unmodellable section sets resolved false
    and yields no rows.
    """
    result: JsonObject = {
        "globals": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "imported_count": 0,
        "resolved": True,
        "scan_capped": False,
    }
    sections, _ = _collect_sections(data)
    imported = _count_imported_globals(sections.get(2))
    result["imported_count"] = imported
    if 6 not in sections:
        return result
    try:
        parsed, capped = _parse_globals(sections[6])
    except (_WasmTruncated, _WasmMalformed):
        result["resolved"] = False
        return result

    for local_index, row in enumerate(parsed):
        row["index"] = imported + local_index
    result["total"] = len(parsed)
    result["scan_capped"] = capped

    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_GLOBALS_PAGE))
    window = parsed[start : start + cap]
    result["globals"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(parsed)
    return result


_MAX_EXPORTS_COLLECT = 5000
_MAX_EXPORTS_PAGE = 2000


def _parse_export_entries(payload: bytes) -> tuple[list[JsonObject], bool]:
    """Decode the export section into every {name, kind, index}, bounded."""
    count, pos = _uleb(payload, 0)
    entries: list[JsonObject] = []
    capped = False
    for _ in range(count):
        if len(entries) >= _MAX_EXPORTS_COLLECT:
            capped = True
            break
        field, pos = _name(payload, pos)
        kind_byte, pos = _u8(payload, pos)
        index, pos = _uleb(payload, pos)
        entries.append(
            {
                "name": field,
                "kind": _EXTERN_KINDS.get(kind_byte, f"0x{kind_byte:02x}"),
                "index": index,
            }
        )
    return entries, capped


def list_wasm_exports(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a module's exports, resolving function exports to their signatures.

    summary lists exports by name/kind/index; this resolves each function export
    through the function index space (imports first, then defined) to its
    params/results and marks whether it resolves to an imported or a defined
    function, attaching the internal name from the name section when present.
    Never raises: an unmodellable type section drops params/results and sets
    types_resolved false.
    """
    result: JsonObject = {
        "exports": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "imported_func_count": 0,
        "types_resolved": True,
        "scan_capped": False,
    }
    sections, name_payload = _collect_sections(data)

    types: list[tuple[list[str], list[str]]] | None = None
    if 1 in sections:
        try:
            types = _parse_types(sections[1])
        except (_WasmTruncated, _WasmMalformed):
            types = None
            result["types_resolved"] = False

    func_imports: list[tuple[str, str, int]] = []
    if 2 in sections:
        try:
            func_imports = _parse_func_imports(sections[2])
        except (_WasmTruncated, _WasmMalformed):
            func_imports = []
    defined: list[int] = []
    if 3 in sections:
        try:
            defined = _parse_function_section(sections[3])
        except (_WasmTruncated, _WasmMalformed):
            defined = []
    func_type_index = [type_index for _, _, type_index in func_imports] + defined
    imported_func_count = len(func_imports)
    result["imported_func_count"] = imported_func_count

    func_names: dict[int, str] = {}
    if name_payload is not None:
        try:
            func_names = _parse_function_names(name_payload)
        except (_WasmTruncated, _WasmMalformed):
            func_names = {}

    if 7 not in sections:
        return result
    try:
        entries, capped = _parse_export_entries(sections[7])
    except (_WasmTruncated, _WasmMalformed):
        return result
    result["scan_capped"] = capped

    for entry in entries:
        if entry["kind"] != "func":
            continue
        index = entry["index"]
        entry["origin"] = "imported" if index < imported_func_count else "defined"
        if 0 <= index < len(func_type_index):
            type_index = func_type_index[index]
            entry["type_index"] = type_index
            if types is not None and 0 <= type_index < len(types):
                params, results = types[type_index]
                entry["params"] = list(params)
                entry["results"] = list(results)
        if index in func_names:
            entry["internal_name"] = func_names[index]

    result["total"] = len(entries)
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_EXPORTS_PAGE))
    window = entries[start : start + cap]
    result["exports"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(entries)
    return result


_MAX_IMPORTS_PAGE = 2000


def list_wasm_imports(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a module's imports with full descriptors, resolving func signatures.

    summary caps the import list and does not resolve function types; this pages
    the whole import section and, for each function import, resolves its
    type_index to params/results and assigns func_index (its slot in the
    function index space, which imports occupy first). Table/memory/global
    imports carry their descriptors (element_type+limits, limits, value_type+
    mutable). Never raises: an unmodellable type section drops params/results and
    sets types_resolved false.
    """
    result: JsonObject = {
        "imports": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "imported_func_count": 0,
        "types_resolved": True,
        "scan_capped": False,
    }
    sections, _ = _collect_sections(data)

    types: list[tuple[list[str], list[str]]] | None = None
    if 1 in sections:
        try:
            types = _parse_types(sections[1])
        except (_WasmTruncated, _WasmMalformed):
            types = None
            result["types_resolved"] = False

    if 2 not in sections:
        return result
    try:
        items, _kinds, capped = _parse_imports(sections[2])
    except (_WasmTruncated, _WasmMalformed):
        return result
    result["scan_capped"] = capped

    func_index = 0
    for item in items:
        if item.get("kind") != "func":
            continue
        item["func_index"] = func_index
        func_index += 1
        type_index = item.get("type_index")
        if types is not None and isinstance(type_index, int) and 0 <= type_index < len(types):
            params, results = types[type_index]
            item["params"] = list(params)
            item["results"] = list(results)
    result["imported_func_count"] = func_index

    result["total"] = len(items)
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_IMPORTS_PAGE))
    window = items[start : start + cap]
    result["imports"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(items)
    return result


_MAX_ELEMENTS_COLLECT = 5000
_MAX_ELEMENTS_PAGE = 2000
_MAX_ELEM_ENTRIES = 4096


def _parse_element_segments(payload: bytes) -> tuple[list[JsonObject], bool]:
    """Decode the element section (id 9) into table-init segments.

    Handles the eight bulk-memory/reference-types encodings (flags 0..7),
    covering active/passive/declarative modes and both the funcidx-vector and
    element-expression forms. For each segment the function indices it installs
    are the ``call_indirect`` dispatch table -- the map from table slot to the
    function a stripped module dispatches through.
    """
    count, pos = _uleb(payload, 0)
    out: list[JsonObject] = []
    capped = False
    for seg_index in range(count):
        if len(out) >= _MAX_ELEMENTS_COLLECT:
            capped = True
            break
        flags, pos = _uleb(payload, pos)

        mode = "active"
        if flags in (1, 5):
            mode = "passive"
        elif flags in (3, 7):
            mode = "declarative"

        table_index: int | None = 0
        if flags in (2, 6):
            table_index, pos = _uleb(payload, pos)
        elif flags in (1, 3, 5, 7):
            table_index = None

        offset_expr: JsonObject | None = None
        if flags in (0, 2, 4, 6):
            offset_expr, pos = _read_const_init(payload, pos)

        element_type = "funcref"
        if flags in (1, 2, 3):
            kind, pos = _u8(payload, pos)
            element_type = "funcref" if kind == 0x00 else f"elemkind:0x{kind:02x}"
        elif flags in (5, 6, 7):
            reftype, pos = _u8(payload, pos)
            element_type = _valtype(reftype)

        use_expr = flags in (4, 5, 6, 7)
        declared, pos = _uleb(payload, pos)
        entries: list[int | None] = []
        entries_truncated = False
        for _ in range(declared):
            if use_expr:
                init, pos = _read_const_init(payload, pos)
                idx = init.get("index") if init.get("op") == "ref.func" else None
            else:
                idx, pos = _uleb(payload, pos)
            if len(entries) < _MAX_ELEM_ENTRIES:
                entries.append(idx)
            else:
                entries_truncated = True

        out.append(
            {
                "index": seg_index,
                "mode": mode,
                "table_index": table_index,
                "offset": offset_expr,
                "element_type": element_type,
                "func_indices": entries,
                "count": declared,
                "entries_truncated": entries_truncated,
            }
        )
    return out, capped


def list_wasm_elements(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List element segments: the indirect-call dispatch table of a WASM module.

    summary only counts element segments; this decodes each one's table-slot map
    so a caller can resolve ``call_indirect`` targets in a stripped module. Never
    raises: a malformed section yields an empty listing.
    """
    result: JsonObject = {
        "elements": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "scan_capped": False,
    }
    sections, _ = _collect_sections(data)
    if 9 not in sections:
        return result
    try:
        segments, capped = _parse_element_segments(sections[9])
    except (_WasmTruncated, _WasmMalformed):
        return result
    result["scan_capped"] = capped
    result["total"] = len(segments)
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_ELEMENTS_PAGE))
    window = segments[start : start + cap]
    result["elements"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(segments)
    return result


_MAX_DATA_SEGMENTS_COLLECT = 5000
_MAX_DATA_PAGE = 1000
_DATA_PREVIEW_BYTES = 64


def _parse_data_segments_detailed(payload: bytes) -> tuple[list[JsonObject], bool]:
    """Decode the data section (id 11) keeping each segment's mode and offset.

    Unlike the string-extraction split, this preserves the linear-memory offset
    an active segment is copied to, so a memory read at runtime can be traced
    back to the source constant that seeded it.
    """
    count, pos = _uleb(payload, 0)
    out: list[JsonObject] = []
    capped = False
    for index in range(count):
        if len(out) >= _MAX_DATA_SEGMENTS_COLLECT:
            capped = True
            break
        flag, pos = _uleb(payload, pos)
        mode = "active"
        memory_index: int | None = 0
        offset_expr: JsonObject | None = None
        if flag == 0:  # active, memory 0
            offset_expr, pos = _read_const_init(payload, pos)
        elif flag == 1:  # passive
            mode = "passive"
            memory_index = None
        elif flag == 2:  # active, explicit memory index
            memory_index, pos = _uleb(payload, pos)
            offset_expr, pos = _read_const_init(payload, pos)
        else:
            raise _WasmMalformed
        length, pos = _uleb(payload, pos)
        end = pos + length
        if end > len(payload):
            raise _WasmTruncated
        out.append(
            {
                "index": index,
                "mode": mode,
                "memory_index": memory_index,
                "offset": offset_expr,
                "blob": payload[pos:end],
            }
        )
        pos = end
    return out, capped


def list_wasm_data(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a module's data segments with memory offsets, sizes and previews.

    summary only counts data segments and wasm.strings pulls printable runs out
    of them; this lays out the segment table itself -- where each blob lands in
    linear memory (the active-segment offset), how large it is, and a bounded hex
    and text preview -- so a memory read can be tied to its seeding constant.
    Never raises: a malformed section yields an empty listing.
    """
    result: JsonObject = {
        "segments": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "scan_capped": False,
    }
    sections, _ = _collect_sections(data)
    if 11 not in sections:
        return result
    try:
        segments, capped = _parse_data_segments_detailed(sections[11])
    except (_WasmTruncated, _WasmMalformed):
        return result
    result["scan_capped"] = capped
    result["total"] = len(segments)
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_DATA_PAGE))
    window = segments[start : start + cap]
    rows: list[JsonObject] = []
    for seg in window:
        blob = seg["blob"]
        preview = blob[:_DATA_PREVIEW_BYTES]
        text = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in preview)
        rows.append(
            {
                "index": seg["index"],
                "mode": seg["mode"],
                "memory_index": seg["memory_index"],
                "offset": seg["offset"],
                "size": len(blob),
                "hex": preview.hex(),
                "text": text,
                "preview_truncated": len(blob) > _DATA_PREVIEW_BYTES,
            }
        )
    result["segments"] = rows
    result["count"] = len(rows)
    result["offset"] = start
    result["has_more"] = start + len(rows) < len(segments)
    return result


_MAX_NAMES_PAGE = 1000
_MAX_LOCAL_FUNCS = 200
_MAX_LOCALS_PER_FUNC = 100


def list_wasm_names(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Recover the symbol table from a module's ``name`` custom section.

    The single most valuable thing on a module that kept its names: the module
    name, the function names (subsection 1 -- the same names the function
    listing borrows, here as a direct index->name map) and, crucially, the local
    and argument names per function (subsection 2), which the function listing
    does not surface and which make a decompilation readable. has_name_section
    is false on a stripped module. Never raises: a malformed subsection is
    skipped and its portion of the table comes back empty.
    """
    result: JsonObject = {
        "has_name_section": False,
        "module": None,
        "functions": [],
        "function_count": 0,
        "function_total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "locals": [],
        "local_function_count": 0,
        "locals_truncated": False,
    }
    _, name_payload = _collect_sections(data)
    if name_payload is None:
        return result
    result["has_name_section"] = True
    try:
        result["module"] = _module_name(name_payload)
    except (_WasmTruncated, _WasmMalformed):
        result["module"] = None
    try:
        func_names = _parse_function_names(name_payload)
    except (_WasmTruncated, _WasmMalformed):
        func_names = {}
    entries = [{"index": index, "name": name} for index, name in sorted(func_names.items())]
    result["function_total"] = len(entries)
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_NAMES_PAGE))
    window = entries[start : start + cap]
    result["functions"] = window
    result["function_count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(entries)
    try:
        local_names = _parse_local_names(name_payload)
    except (_WasmTruncated, _WasmMalformed):
        local_names = {}
    locals_out: list[JsonObject] = []
    locals_truncated = False
    for func_index in sorted(local_names):
        if len(locals_out) >= _MAX_LOCAL_FUNCS:
            locals_truncated = True
            break
        pairs = local_names[func_index]
        names = [
            {"index": local_index, "name": local_name}
            for local_index, local_name in pairs[:_MAX_LOCALS_PER_FUNC]
        ]
        locals_out.append(
            {
                "function": func_index,
                "names": names,
                "name_count": len(names),
                "names_truncated": len(pairs) > _MAX_LOCALS_PER_FUNC,
            }
        )
    result["locals"] = locals_out
    result["local_function_count"] = len(locals_out)
    result["locals_truncated"] = locals_truncated
    return result


_MAX_TABLES_COLLECT = 5000
_MAX_TABLES_PAGE = 2000


def _parse_table_imports(payload: bytes) -> list[JsonObject]:
    """Extract imported tables (they precede defined ones in the index space)."""
    out: list[JsonObject] = []
    count, pos = _uleb(payload, 0)
    for _ in range(count):
        module, pos = _name(payload, pos)
        field, pos = _name(payload, pos)
        kind, pos = _u8(payload, pos)
        if kind == 0:  # func: type index
            _, pos = _uleb(payload, pos)
        elif kind == 1:  # table: reftype + limits
            reftype, pos = _u8(payload, pos)
            limits, pos = _limits(payload, pos)
            out.append(
                {
                    "origin": "imported",
                    "module": module,
                    "name": field,
                    "element_type": _valtype(reftype),
                    "limits": limits,
                }
            )
        elif kind == 2:  # memory: limits
            _, pos = _limits(payload, pos)
        elif kind == 3:  # global: valtype + mutability
            _, pos = _u8(payload, pos)
            _, pos = _u8(payload, pos)
        else:
            break
    return out


def _parse_tables(payload: bytes) -> tuple[list[JsonObject], bool]:
    """Decode the table section (id 4): a vector of (reftype, limits) records."""
    count, pos = _uleb(payload, 0)
    out: list[JsonObject] = []
    capped = False
    for _ in range(count):
        if len(out) >= _MAX_TABLES_COLLECT:
            capped = True
            break
        reftype, pos = _u8(payload, pos)
        limits, pos = _limits(payload, pos)
        out.append(
            {
                "origin": "defined",
                "module": None,
                "name": None,
                "element_type": _valtype(reftype),
                "limits": limits,
            }
        )
    return out, capped


def list_wasm_tables(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a module's tables (section 4) with their reftype and limits.

    Tables are the one section type the other listers do not cover on its own:
    summary reports memory and start, globals/functions/exports/imports/elements/
    data each have a tool, but the table definitions -- the indirect-call
    dispatch tables that wasm.elements populates -- were only visible as import
    rows. This walks the whole table index space (imported tables first, then
    defined), giving each its element_type (funcref/externref) and limits. Never
    raises: an unmodellable table section sets resolved false while imported
    tables still list.
    """
    result: JsonObject = {
        "tables": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "imported_count": 0,
        "defined_count": 0,
        "resolved": True,
        "scan_capped": False,
    }
    sections, _ = _collect_sections(data)
    imported: list[JsonObject] = []
    if 2 in sections:
        try:
            imported = _parse_table_imports(sections[2])
        except (_WasmTruncated, _WasmMalformed):
            imported = []
    defined: list[JsonObject] = []
    capped = False
    if 4 in sections:
        try:
            defined, capped = _parse_tables(sections[4])
        except (_WasmTruncated, _WasmMalformed):
            result["resolved"] = False
            defined = []
    all_tables = imported + defined
    for index, row in enumerate(all_tables):
        row["index"] = index
    result["imported_count"] = len(imported)
    result["defined_count"] = len(defined)
    result["total"] = len(all_tables)
    result["scan_capped"] = capped
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_TABLES_PAGE))
    window = all_tables[start : start + cap]
    result["tables"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(all_tables)
    return result


_MAX_CODE_COLLECT = 50_000
_MAX_CODE_PAGE = 2000
_MAX_LOCAL_GROUPS = 100


def _parse_code_section(payload: bytes) -> tuple[list[JsonObject], bool]:
    """Decode the code section (id 10): one body per defined function.

    Each body is a size-prefixed blob whose head is a vector of local
    declaration groups (count + valtype); the rest is the instruction stream.
    We do not disassemble -- the useful triage signal is the body size (a giant
    function is the shape of a VM interpreter or an unrolled/obfuscated blob)
    and the local layout, so we read the locals vector and skip past the body
    by the declared size, which also resyncs cleanly across a malformed head.
    """
    count, pos = _uleb(payload, 0)
    out: list[JsonObject] = []
    capped = False
    for _ in range(count):
        if len(out) >= _MAX_CODE_COLLECT:
            capped = True
            break
        body_size, pos = _uleb(payload, pos)
        end = pos + body_size
        if end > len(payload):
            raise _WasmTruncated
        bpos = pos
        groups: list[JsonObject] = []
        total_locals = 0
        groups_truncated = False
        try:
            group_count, bpos = _uleb(payload, bpos)
            for _ in range(group_count):
                # The locals vector lives at the head of the body; never let a
                # hostile group_count march the reader into the instructions.
                if bpos >= end:
                    groups_truncated = True
                    break
                n, bpos = _uleb(payload, bpos)
                vt, bpos = _u8(payload, bpos)
                total_locals += n
                if len(groups) < _MAX_LOCAL_GROUPS:
                    groups.append({"count": n, "type": _valtype(vt)})
                else:
                    groups_truncated = True
        except (_WasmTruncated, _WasmMalformed):
            groups_truncated = True
        out.append(
            {
                "body_size": body_size,
                "local_count": total_locals,
                "local_groups": groups,
                "local_groups_truncated": groups_truncated,
            }
        )
        pos = end
    return out, capped


def list_wasm_code(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List per-function code bodies (section 10): body size and local layout.

    The code section is the one big section no other tool exposes: functions
    lists signatures, this lists what each defined function actually weighs.
    Each row is keyed to the function index (imported functions have no body,
    so indices start after them), carries the body_size in bytes and the local
    declaration groups, and picks up the debug name from the name section when
    present. body_size is the fastest obfuscation tell in a wasm module -- one
    function dwarfing the rest is the classic interpreter/packed-blob shape.
    Never raises: a malformed code section sets resolved false and returns what
    parsed.
    """
    result: JsonObject = {
        "functions": [],
        "count": 0,
        "total": 0,
        "offset": max(0, int(offset)),
        "has_more": False,
        "imported_count": 0,
        "resolved": True,
        "scan_capped": False,
    }
    sections, name_payload = _collect_sections(data)

    imported_count = 0
    if 2 in sections:
        try:
            imported_count = len(_parse_func_imports(sections[2]))
        except (_WasmTruncated, _WasmMalformed):
            imported_count = 0

    func_names: dict[int, str] = {}
    if name_payload is not None:
        try:
            func_names = _parse_function_names(name_payload)
        except (_WasmTruncated, _WasmMalformed):
            func_names = {}

    bodies: list[JsonObject] = []
    capped = False
    if 10 in sections:
        try:
            bodies, capped = _parse_code_section(sections[10])
        except (_WasmTruncated, _WasmMalformed):
            result["resolved"] = False
            bodies = []

    for i, row in enumerate(bodies):
        index = imported_count + i
        row["index"] = index
        if index in func_names:
            row["name"] = func_names[index]

    result["imported_count"] = imported_count
    result["total"] = len(bodies)
    result["scan_capped"] = capped
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_CODE_PAGE))
    window = bodies[start : start + cap]
    result["functions"] = window
    result["count"] = len(window)
    result["offset"] = start
    result["has_more"] = start + len(window) < len(bodies)
    return result
