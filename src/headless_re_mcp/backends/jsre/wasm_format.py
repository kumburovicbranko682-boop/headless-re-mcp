"""Dependency-free WebAssembly binary reader for a module's import/export surface.

``wasm.imports`` / ``wasm.exports`` answer the two questions a WASM reverse
engineer asks first -- what host functions/globals/memories/tables the module
depends on, and what it exposes back to the host -- straight from the module's
binary sections. Reading the bytes (the format is a stable spec) instead of
scraping ``wasm-objdump`` text means these work with no wabt install and cannot
drift with a wabt version.

The reader is bounded end to end because a ``.wasm`` is attacker-controlled
input: every slice is checked against the buffer, LEB128 is width-capped so a
run of continuation bytes cannot spin, and vector counts and names are capped so
a hostile or truncated module yields a partial-but-flagged answer rather than an
unbounded read, a giant allocation, or a crash. The public helpers therefore
never raise on bad input -- they stop and report ``incomplete`` -- except for a
file that is not a WebAssembly module at all.
"""

from __future__ import annotations

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

# Bounds. These sit far above any real module's import/export/type counts, so a
# legitimate module is parsed whole; they exist only to cap a hostile count.
_MAX_ENTRIES = 8192
_MAX_TYPES = 8192
_MAX_VALTYPES = 1024
_MAX_NAME_CHARS = 512
# The largest declared vector length worth attempting before calling the module
# malformed: 2^24 dwarfs any real section yet bounds the loop cheaply.
_MAX_VEC = 1 << 24


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

    def name(self) -> str:
        length = self.uleb()
        if length > _MAX_VEC:
            raise _Truncated
        raw = self.take(length)
        text = raw.decode("utf-8", "replace")
        return text[:_MAX_NAME_CHARS]


class _Truncated(Exception):
    """Internal: a read hit the end of the buffer; stop and flag incomplete."""


def _walk_sections(data: bytes) -> dict[int, bytes]:
    """Map each top-level section id to its body (last occurrence wins).

    The generic walk consumes each section by its declared size, so custom
    sections (id 0) and any section we do not decode are skipped for free. A
    section whose declared size runs past the buffer ends the walk -- we return
    what we gathered rather than failing the whole read.
    """
    if len(data) < 8 or data[:4] != _MAGIC:
        raise WasmParseError("not a WebAssembly module")
    reader = _Reader(data, pos=8)  # 4-byte magic + 4-byte version
    sections: dict[int, bytes] = {}
    try:
        while not reader.at_end():
            section_id = reader.byte()
            size = reader.uleb()
            body = reader.take(size)
            sections[section_id] = body
    except _Truncated:
        pass
    return sections


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
