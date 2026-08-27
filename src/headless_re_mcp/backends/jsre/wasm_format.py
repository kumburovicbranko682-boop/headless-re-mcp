"""Dependency-free WebAssembly binary reader for a module's static surface.

``wasm.imports`` / ``wasm.exports`` answer the two questions a WASM reverse
engineer asks first -- what host functions/globals/memories/tables the module
depends on, and what it exposes back to the host -- while ``wasm.sections`` maps
the module's layout, ``wasm.functions`` lists the defined-function table with
resolved signatures and names, ``wasm.names`` symbolises it from the custom name
section, and ``wasm.strings`` pulls the Data-section literal pool. All read the
module's binary sections directly. Reading the bytes (the format is a stable spec)
instead of scraping ``wasm-objdump`` text means these work with no wabt install
and cannot drift with a wabt version.

The reader is bounded end to end because a ``.wasm`` is attacker-controlled
input: every slice is checked against the buffer, LEB128 is width-capped so a
run of continuation bytes cannot spin, and vector counts and names are capped so
a hostile or truncated module yields a partial-but-flagged answer rather than an
unbounded read, a giant allocation, or a crash. The public helpers therefore
never raise on bad input -- they stop and report ``incomplete`` -- except for a
file that is not a WebAssembly module at all.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import suppress
from typing import Any

JsonObject = dict[str, Any]

_MAGIC = b"\x00asm"
# Value types (numeric + reference); anything else renders as its hex byte so an
# unknown/future type is visible rather than silently dropped.
_VALTYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}
# Well-known top-level section ids (WASM spec through 2.0). An unknown id renders
# as its hex byte so a future/nonstandard section is visible, not dropped.
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
# Sections whose body begins with a LEB128 vector count, so a cheap leading read
# yields how many entries the section declares. custom(0) leads with a name,
# start(8) is a single funcidx, and data_count(12) is itself a single count --
# all handled apart from this set.
_VECTOR_SECTIONS = frozenset({1, 2, 3, 4, 5, 6, 7, 9, 10, 11})

# Bounds. These sit far above any real module's import/export/type counts, so a
# legitimate module is parsed whole; they exist only to cap a hostile count.
_MAX_ENTRIES = 8192
_MAX_TYPES = 8192
_MAX_VALTYPES = 1024
_MAX_NAME_CHARS = 512
# The largest declared vector length worth attempting before calling the module
# malformed: 2^24 dwarfs any real section yet bounds the loop cheaply.
_MAX_VEC = 1 << 24

# Data-section string extraction bounds. A printable run longer than this is
# clipped and restarted (a hostile segment can be one very long "string"), and
# the number of distinct strings collected is capped so a giant Data section
# yields a partial-but-flagged list rather than an unbounded set.
_DATA_SECTION_ID = 11
_MAX_STRING_CHARS = 256
_MAX_DATA_STRINGS = 4096
# Constant-expression opcodes we step over to reach a data segment's bytes. An
# active segment's memory offset is a const expr terminated by ``end`` (0x0b);
# we only skip it, so each opcode maps to how its immediate is encoded -- a
# single LEB, or a fixed number of bytes.
_END_OP = 0x0B
_CONST_LEB_OPS = frozenset({0x41, 0x42, 0x23, 0xD2})  # i32/i64.const, global.get, ref.func
_CONST_FIXED_OPS = {0x43: 4, 0x44: 8, 0xD0: 1}  # f32.const, f64.const, ref.null


class WasmParseError(Exception):
    """The bytes are not a WebAssembly module we can read at all."""


def _valtype(byte: int) -> str:
    return _VALTYPES.get(byte, f"0x{byte:02x}")


class _Reader:
    """A bounds-checked cursor over the module bytes.

    Every read that could run past the end raises ``_Truncated`` so callers can
    stop cleanly and mark the result incomplete; nothing here allocates on an
    attacker-supplied length without first checking it against the buffer.
    """

    __slots__ = ("data", "pos", "n")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos
        self.n = len(data)

    def at_end(self) -> bool:
        return self.pos >= self.n

    def byte(self) -> int:
        if self.pos >= self.n:
            raise _Truncated
        value = self.data[self.pos]
        self.pos += 1
        return value

    def uleb(self, *, max_bits: int = 32) -> int:
        result = 0
        shift = 0
        while True:
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            # A u32/u33 index or length never needs more than five 7-bit groups;
            # refusing past that stops a padded-continuation-byte run cold.
            if shift > max_bits:
                raise _Truncated

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > self.n:
            raise _Truncated
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def skip_leb(self, *, max_bytes: int = 10) -> None:
        # Consume a LEB128 immediate we do not need the value of (a const-expr
        # operand). Ten 7-bit groups cover a 64-bit integer; refusing past that
        # stops a padded-continuation-byte run just like uleb.
        for _ in range(max_bytes):
            if not self.byte() & 0x80:
                return
        raise _Truncated

    def name(self) -> str:
        length = self.uleb()
        if length > _MAX_VEC:
            raise _Truncated
        raw = self.take(length)
        text = raw.decode("utf-8", "replace")
        return text[:_MAX_NAME_CHARS]


class _Truncated(Exception):
    """Internal: a read hit the end of the buffer; stop and flag incomplete."""


def _module_reader(data: bytes) -> _Reader:
    """A reader positioned just past the 8-byte header, or reject a non-module."""
    if len(data) < 8 or data[:4] != _MAGIC:
        raise WasmParseError("not a WebAssembly module")
    return _Reader(data, pos=8)  # 4-byte magic + 4-byte version


def _walk_sections(data: bytes) -> dict[int, bytes]:
    """Map each non-custom section id to its body (last occurrence wins).

    The generic walk consumes each section by its declared size, so custom
    sections (id 0) and any section we do not decode are skipped for free. A
    section whose declared size runs past the buffer ends the walk -- we return
    what we gathered rather than failing the whole read. Custom sections (id 0)
    all share one id and would clobber each other here, so a caller after a
    specific one (e.g. "name") uses :func:`_find_custom_section` instead.
    """
    reader = _module_reader(data)
    sections: dict[int, bytes] = {}
    try:
        while not reader.at_end():
            section_id = reader.byte()
            size = reader.uleb()
            body = reader.take(size)
            if section_id != 0:
                sections[section_id] = body
    except _Truncated:
        pass
    return sections


def _find_custom_section(data: bytes, target: str) -> bytes | None:
    """Payload (after its name) of the first custom section named ``target``.

    Custom sections all carry id 0 and lead with their own name, so this walks
    every section, and for each id-0 one reads that leading name and returns the
    remaining bytes when it matches. Returns ``None`` when no such section is
    present -- the common "stripped module" case for the name section.
    """
    reader = _module_reader(data)
    try:
        while not reader.at_end():
            section_id = reader.byte()
            size = reader.uleb()
            body = reader.take(size)
            if section_id != 0:
                continue
            sub = _Reader(body)
            try:
                name = sub.name()
            except _Truncated:
                continue
            if name == target:
                return body[sub.pos :]
    except _Truncated:
        pass
    return None


def _read_valtypes(reader: _Reader) -> list[str]:
    count = reader.uleb()
    if count > _MAX_VALTYPES:
        raise _Truncated
    return [_valtype(reader.byte()) for _ in range(count)]


def _parse_types(body: bytes | None) -> list[tuple[list[str], list[str]]]:
    """Function signatures from the Type section, for resolving func imports.

    Only function types (form ``0x60``) exist through the WASM 2.0 spec; a
    different form ends the parse (we keep the signatures gathered so far), since
    an import referencing a later type simply reads back without params/results.
    """
    if not body:
        return []
    reader = _Reader(body)
    types: list[tuple[list[str], list[str]]] = []
    try:
        count = reader.uleb()
        for _ in range(min(count, _MAX_TYPES)):
            if reader.byte() != 0x60:
                break
            params = _read_valtypes(reader)
            results = _read_valtypes(reader)
            types.append((params, results))
    except _Truncated:
        pass
    return types


def _read_limits(reader: _Reader) -> JsonObject:
    flag = reader.byte()
    minimum = reader.uleb()
    limits: JsonObject = {"min": minimum}
    if flag & 0x01:
        limits["max"] = reader.uleb()
    return limits


def parse_imports(data: bytes) -> tuple[list[JsonObject], int, bool]:
    """``(entries, declared_count, incomplete)`` for the module's Import section.

    Each entry has module, name and kind; a func import also carries its
    type_index and (when the Type section resolved it) params/results; a table,
    memory or global import carries the type detail for its kind. ``incomplete``
    is true when the section was truncated mid-parse or the declared count
    exceeded the entry cap, so a caller never reads a short list as the whole
    import surface.
    """
    sections = _walk_sections(data)
    types = _parse_types(sections.get(1))
    body = sections.get(2)
    if not body:
        return [], 0, False
    reader = _Reader(body)
    entries: list[JsonObject] = []
    declared = 0
    incomplete = False
    try:
        declared = reader.uleb()
        if declared > _MAX_VEC:
            raise _Truncated
        limit = min(declared, _MAX_ENTRIES)
        incomplete = declared > limit
        for _ in range(limit):
            module = reader.name()
            field = reader.name()
            kind_byte = reader.byte()
            entry: JsonObject = {
                "module": module,
                "name": field,
                "kind": _KINDS.get(kind_byte, f"0x{kind_byte:02x}"),
            }
            if kind_byte == 0:  # func
                type_index = reader.uleb()
                entry["type_index"] = type_index
                if 0 <= type_index < len(types):
                    params, results = types[type_index]
                    entry["params"] = params
                    entry["results"] = results
            elif kind_byte == 1:  # table
                entry["element_type"] = _valtype(reader.byte())
                entry["limits"] = _read_limits(reader)
            elif kind_byte == 2:  # memory
                entry["limits"] = _read_limits(reader)
            elif kind_byte == 3:  # global
                entry["value_type"] = _valtype(reader.byte())
                entry["mutable"] = reader.byte() == 1
            else:
                # An unknown import kind means we no longer know the byte layout
                # of the rest of the section, so stop rather than misparse it.
                entries.append(entry)
                incomplete = True
                return entries, declared, incomplete
            entries.append(entry)
    except _Truncated:
        incomplete = True
    return entries, declared, incomplete


def parse_exports(data: bytes) -> tuple[list[JsonObject], int, bool]:
    """``(entries, declared_count, incomplete)`` for the module's Export section.

    Each entry has name, kind and index (into that kind's index space). Bounded
    and incomplete-flagged the same way as :func:`parse_imports`.
    """
    sections = _walk_sections(data)
    body = sections.get(7)
    if not body:
        return [], 0, False
    reader = _Reader(body)
    entries: list[JsonObject] = []
    declared = 0
    incomplete = False
    try:
        declared = reader.uleb()
        if declared > _MAX_VEC:
            raise _Truncated
        limit = min(declared, _MAX_ENTRIES)
        incomplete = declared > limit
        for _ in range(limit):
            name = reader.name()
            kind_byte = reader.byte()
            index = reader.uleb()
            entries.append(
                {
                    "name": name,
                    "kind": _KINDS.get(kind_byte, f"0x{kind_byte:02x}"),
                    "index": index,
                }
            )
    except _Truncated:
        incomplete = True
    return entries, declared, incomplete


def parse_names(data: bytes) -> tuple[bool, str | None, list[JsonObject], bool]:
    """``(present, module_name, function_names, incomplete)`` from the name section.

    The custom "name" section is what makes a stripped-but-named module readable:
    it maps function indices to debug names (and optionally names the module).
    Absent it, internal functions are only indices, so this is the single biggest
    symbolication win a WASM read can offer. ``present`` is whether the section
    exists at all (false for the common stripped module, distinct from a section
    that is present but carries no function names). ``function_names`` is the
    name-map subsection 1, each row ``{index, name}`` sorted by index. Bounded and
    ``incomplete``-flagged like the sibling parsers; unknown subsections (locals,
    types, ...) are skipped by their declared size.
    """
    payload = _find_custom_section(data, "name")
    if payload is None:
        return False, None, [], False
    reader = _Reader(payload)
    module_name: str | None = None
    function_names: list[JsonObject] = []
    incomplete = False
    try:
        while not reader.at_end():
            sub_id = reader.byte()
            sub_body = reader.take(reader.uleb())
            if sub_id == 0:  # module name
                try:
                    module_name = _Reader(sub_body).name()
                except _Truncated:
                    incomplete = True
            elif sub_id == 1:  # function name map: vec of (funcidx, name)
                sub = _Reader(sub_body)
                try:
                    count = sub.uleb()
                    if count > _MAX_VEC:
                        raise _Truncated
                    limit = min(count, _MAX_ENTRIES)
                    if count > limit:
                        incomplete = True
                    for _ in range(limit):
                        index = sub.uleb()
                        function_names.append({"index": index, "name": sub.name()})
                except _Truncated:
                    incomplete = True
            # Other subsections (2=locals, 4=type, 7=global, ...) are consumed by
            # size above and intentionally not decoded here.
    except _Truncated:
        incomplete = True
    function_names.sort(key=lambda row: row["index"])
    return True, module_name, function_names, incomplete


def _count_imported_functions(data: bytes) -> int:
    """How many functions the Import section declares (the func-index offset).

    Function indices are imported-functions-first, so a defined function's
    absolute index is this count plus its position in the Function section.
    Reuses :func:`parse_imports` so the count matches what wasm.imports reports.
    """
    entries, _declared, _incomplete = parse_imports(data)
    return sum(1 for entry in entries if entry.get("kind") == "func")


def _function_name_map(data: bytes) -> dict[int, str]:
    """funcidx -> debug name from the custom name section, empty when stripped."""
    _present, _module_name, function_names, _incomplete = parse_names(data)
    return {int(row["index"]): str(row["name"]) for row in function_names}


def parse_functions(data: bytes) -> tuple[list[JsonObject], int, bool]:
    """``(entries, declared_count, incomplete)`` for the module's defined functions.

    The Function section (id 3) lists one type index per function the module
    *defines*; imported functions are not repeated there. Function indices are
    imported-functions-first, so a defined function's absolute index is
    imported_func_count + its position here -- and that absolute index is what
    the name section and call instructions use, so it is what this reports.
    Each entry carries index (absolute) and type_index, plus params/results when
    the Type section resolves that index, and name when the custom name section
    names it. This is the function table a reverse engineer navigates: without
    it internal functions are only indices with no signature or name.
    ``incomplete`` is flagged like the sibling parsers when the section was
    truncated or the declared count exceeded the entry cap.
    """
    sections = _walk_sections(data)
    types = _parse_types(sections.get(1))
    body = sections.get(3)
    if not body:
        return [], 0, False
    imported = _count_imported_functions(data)
    names = _function_name_map(data)
    reader = _Reader(body)
    entries: list[JsonObject] = []
    declared = 0
    incomplete = False
    try:
        declared = reader.uleb()
        if declared > _MAX_VEC:
            raise _Truncated
        limit = min(declared, _MAX_ENTRIES)
        incomplete = declared > limit
        for position in range(limit):
            type_index = reader.uleb()
            absolute = imported + position
            entry: JsonObject = {"index": absolute, "type_index": type_index}
            if 0 <= type_index < len(types):
                params, results = types[type_index]
                entry["params"] = params
                entry["results"] = results
            name = names.get(absolute)
            if name is not None:
                entry["name"] = name
            entries.append(entry)
    except _Truncated:
        incomplete = True
    return entries, declared, incomplete


def parse_sections(data: bytes) -> tuple[list[JsonObject], bool]:
    """``(sections, incomplete)`` for the module's top-level section layout.

    This is the module's structural map, in file order: each row has id, name
    (the well-known section name, or the byte in hex for an unknown id), size
    (the declared body length in bytes) and offset (where that body starts in
    the file). A custom section (id 0) also carries custom_name -- which custom
    section it is ("name", "producers", a ".debug_*" section, ...) -- since all
    custom sections share id 0 and are told apart only by that leading name. A
    vector-prefixed section (type, import, function, table, memory, global,
    export, element, code, data) and the data_count section add count, the
    number of entries the section header declares, read cheaply from the body's
    leading integer without decoding the whole section.

    ``incomplete`` is true when a section's declared size ran past the buffer or
    the section cap was hit before the module ended -- a truncated or hostile
    module -- so the map is read as partial rather than the whole layout. Reads
    of a section's own leading name/count are isolated to that section's body, so
    a section that lies about its internal length just omits custom_name/count
    rather than corrupting the top-level walk. Reading the bytes needs no wabt,
    so this is the dependency-free equivalent of the section table wasm.info
    prints as wasm-objdump text.
    """
    reader = _module_reader(data)
    sections: list[JsonObject] = []
    incomplete = False
    try:
        while not reader.at_end():
            section_id = reader.byte()
            size = reader.uleb()
            body_offset = reader.pos
            # take() raises _Truncated when the declared size overruns the
            # buffer, ending the walk with what we gathered rather than misread.
            body = reader.take(size)
            entry: JsonObject = {
                "id": section_id,
                "name": _SECTION_NAMES.get(section_id, f"0x{section_id:02x}"),
                "size": size,
                "offset": body_offset,
            }
            # A section can declare its size honestly yet lie about its own
            # leading name/count; reading those from a sub-reader over the body
            # (already bounds-checked by take) keeps such a lie from corrupting
            # the top-level walk -- we just omit the optional field for that row.
            sub = _Reader(body)
            if section_id == 0:  # custom: body leads with the section's own name
                with suppress(_Truncated):
                    entry["custom_name"] = sub.name()
            elif section_id == 12 or section_id in _VECTOR_SECTIONS:
                # data_count(12) is a single count; the vector sections lead with
                # their entry count. Either way the first integer is the count.
                with suppress(_Truncated):
                    entry["count"] = sub.uleb()
            sections.append(entry)
            if len(sections) >= _MAX_ENTRIES:
                # A real module has a handful of sections, but custom sections
                # are unbounded in number; cap the map like the sibling parsers
                # and flag the truncation when bytes remain.
                incomplete = not reader.at_end()
                break
    except _Truncated:
        incomplete = True
    return sections, incomplete


def _skip_const_expr(reader: _Reader) -> None:
    """Step a data segment's offset init-expr up to its terminating ``end``.

    We do not evaluate the offset, only skip it to reach the segment bytes, so
    each opcode is consumed with its immediate. An opcode we do not recognise
    means the byte layout ahead is unknown, so raise ``_Truncated`` and let the
    caller stop and flag the result rather than misread the following vector
    length as segment data.
    """
    steps = 0
    while True:
        op = reader.byte()
        if op == _END_OP:
            return
        if op in _CONST_LEB_OPS:
            reader.skip_leb()
        elif op in _CONST_FIXED_OPS:
            reader.take(_CONST_FIXED_OPS[op])
        else:
            raise _Truncated
        steps += 1
        if steps > _MAX_VEC:
            raise _Truncated


def _ascii_runs(chunk: bytes, min_len: int) -> Iterator[str]:
    """Yield maximal printable-ASCII runs of at least ``min_len`` characters.

    A run reaching ``_MAX_STRING_CHARS`` is emitted and restarted, so a segment
    that is one very long printable run yields clipped strings rather than a
    single giant one.
    """
    run = bytearray()
    for byte in chunk:
        if 0x20 <= byte < 0x7F:
            run.append(byte)
            if len(run) >= _MAX_STRING_CHARS:
                yield run.decode("ascii")
                run.clear()
            continue
        if len(run) >= min_len:
            yield run.decode("ascii")
        run.clear()
    if len(run) >= min_len:
        yield run.decode("ascii")


def parse_data_strings(data: bytes, *, min_len: int = 4) -> tuple[list[str], int, bool]:
    """``(strings, segment_count, incomplete)`` from the module's Data section.

    Walks each data segment (active or passive, MVP or bulk-memory encoded),
    skips an active segment's offset init-expr, and pulls maximal printable-ASCII
    runs of at least ``min_len`` characters from the segment bytes -- the literal
    pool a WASM module ships (URLs, format strings, error text) read straight
    from the binary with no wabt. Distinct strings are returned sorted.
    ``incomplete`` is true when the section was truncated mid-walk, an unknown
    segment flag or a non-const offset op left the layout unknown, or the
    distinct-string cap was reached, so a partial list is never read as the whole
    literal pool.
    """
    if min_len < 1:
        min_len = 1
    sections = _walk_sections(data)
    body = sections.get(_DATA_SECTION_ID)
    if not body:
        return [], 0, False
    reader = _Reader(body)
    found: set[str] = set()
    segments = 0
    incomplete = False
    capped = False
    try:
        count = reader.uleb()
        if count > _MAX_VEC:
            raise _Truncated
        limit = min(count, _MAX_ENTRIES)
        if count > limit:
            incomplete = True
        for _ in range(limit):
            flag = reader.uleb()
            if flag == 0:  # active, memory 0: offset expr then bytes
                _skip_const_expr(reader)
            elif flag == 1:  # passive: bytes only
                pass
            elif flag == 2:  # active, explicit memidx: memidx, offset expr, bytes
                reader.uleb()
                _skip_const_expr(reader)
            else:
                # An unknown segment flag means the byte layout ahead is unknown.
                incomplete = True
                break
            seg_len = reader.uleb()
            if seg_len > _MAX_VEC:
                raise _Truncated
            chunk = reader.take(seg_len)
            segments += 1
            for text in _ascii_runs(chunk, min_len):
                found.add(text)
                if len(found) >= _MAX_DATA_STRINGS:
                    capped = True
                    break
            if capped:
                break
    except _Truncated:
        incomplete = True
    if capped:
        incomplete = True
    return sorted(found), segments, incomplete
