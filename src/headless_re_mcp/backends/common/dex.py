"""Pure-stdlib structural reader for a standalone Dalvik executable (.dex).

The apk.* tools drive androguard against an APK *container*; a standalone .dex --
one dropped by malware, loaded dynamically at runtime, or pulled out of an APK --
has no reader here at all, and androguard is not always installed. Yet the DEX
header is a fixed 112-byte record and the string, type and class tables are plain
index arrays, all exact and well documented. This module reads them with the
stdlib alone:

- summarize_dex validates the magic, reports the version and section counts and
  returns a bounded, paginated slice of the string table (the class and method
  names and literals an analyst greps first);
- list_dex_classes walks the class-definition table and resolves each class's own
  type descriptor, its superclass, its access flags and its source file -- the
  "what classes are in this dex" inventory that mirrors apk.classes but needs no
  androguard.

The header walk is exact; every table is followed defensively -- an index that
leaves the file contributes a warning, not an exception -- and every field, list
and page is bounded. Strings are decoded best-effort as UTF-8 (DEX stores MUTF-8,
which coincides with UTF-8 for the ASCII identifiers that dominate a class table).
"""

from __future__ import annotations

import struct
from typing import Any

JsonObject = dict[str, Any]

# magic is "dex\n" + a three-digit version + NUL.
_DEX_MAGIC = b"dex\n"
_HEADER_SIZE = 0x70  # 112 bytes
_ENDIAN_CONSTANT = 0x12345678
_REVERSE_ENDIAN = 0x78563412
_NO_INDEX = 0xFFFFFFFF
_CLASS_DEF_SIZE = 32  # bytes per class_def_item

# One returned string, and the bytes scanned to find its terminator, are bounded
# so a pathological table cannot inflate a reply. Real identifiers sit far below.
_MAX_STRING = 4096
_MAX_STRING_SCAN = 1 << 16
_MAX_WARNINGS = 32

# The twenty little-endian u32 that follow the magic, checksum and signature.
_HEADER_FIELDS = (
    "file_size", "header_size", "endian_tag", "link_size", "link_off", "map_off",
    "string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off",
    "proto_ids_size", "proto_ids_off", "field_ids_size", "field_ids_off",
    "method_ids_size", "method_ids_off", "class_defs_size", "class_defs_off",
    "data_size", "data_off",
)

# Class-level access flags worth naming (JVM/Dalvik bit set); the rest are for
# methods/fields and are left to the raw integer.
_CLASS_ACCESS_FLAGS: tuple[tuple[int, str], ...] = (
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
)


class DexParseError(ValueError):
    """Bytes that are not a Dalvik executable.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name. Raised only for the
    header; a bad table index is a warning, not a failure.
    """


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode an unsigned LEB128 at ``pos``; return (value, next_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise DexParseError("truncated LEB128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 35:
            raise DexParseError("LEB128 integer too long")


def _read_string(data: bytes, offset: int) -> str:
    """One MUTF-8 string at ``offset``: a ULEB128 length then bytes up to a NUL."""
    _, pos = _uleb128(data, offset)  # utf16 unit count; the NUL bounds the bytes
    end = data.find(b"\x00", pos, min(len(data), pos + _MAX_STRING_SCAN))
    raw = data[pos:end] if end != -1 else data[pos : pos + _MAX_STRING_SCAN]
    text = raw.decode("utf-8", errors="replace")
    return text[:_MAX_STRING]


def _read_header(data: bytes) -> tuple[str, int, str, dict[str, int]]:
    """Validate the magic and return (version, checksum, signature_hex, fields).

    Raises DexParseError when the bytes are not a Dalvik executable (bad magic or
    a header that does not fit). ``fields`` is the twenty header u32 by name.
    """
    if len(data) < _HEADER_SIZE:
        raise DexParseError("not a DEX file: shorter than a DEX header")
    if data[0:4] != _DEX_MAGIC or data[7] != 0:
        raise DexParseError("not a DEX file: missing the dex\\n magic")
    version = data[4:7].decode("ascii", errors="replace")
    checksum = struct.unpack_from("<I", data, 0x08)[0]
    signature = data[0x0C:0x20].hex()
    values = struct.unpack_from("<20I", data, 0x20)
    return version, checksum, signature, dict(zip(_HEADER_FIELDS, values, strict=True))


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _string_by_index(data: bytes, header: dict[str, int], index: int) -> str | None:
    """The string-table entry at ``index``, or None when it is absent/out of bounds."""
    if index == _NO_INDEX or index >= header["string_ids_size"]:
        return None
    entry = header["string_ids_off"] + index * 4
    if entry + 4 > len(data):
        return None
    string_off = _u32(data, entry)
    if string_off >= len(data):
        return None
    try:
        return _read_string(data, string_off)
    except DexParseError:
        return None


def _type_descriptor(data: bytes, header: dict[str, int], type_index: int) -> str | None:
    """The type descriptor (e.g. ``Lcom/example/Foo;``) at ``type_index``, or None."""
    if type_index == _NO_INDEX or type_index >= header["type_ids_size"]:
        return None
    entry = header["type_ids_off"] + type_index * 4
    if entry + 4 > len(data):
        return None
    return _string_by_index(data, header, _u32(data, entry))


def _decode_class_flags(value: int) -> list[str]:
    return [name for bit, name in _CLASS_ACCESS_FLAGS if value & bit]


def _dotted(descriptor: str | None) -> str:
    """``Lcom/example/Foo;`` -> ``com.example.Foo``; arrays/primitives unchanged."""
    if descriptor and descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor or ""


def summarize_dex(data: bytes, *, offset: int = 0, limit: int = 200) -> JsonObject:
    """Structural summary of a .dex plus a bounded page of its string table.

    Raises DexParseError when the bytes are not a Dalvik executable. The section
    counts come straight from the fixed header; the string page is materialised
    by following the string-id offset array, each entry bounds-checked so a
    corrupt offset is skipped with a warning rather than raising.
    """
    version, checksum, signature, header = _read_header(data)

    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    endian_tag = header["endian_tag"]
    if endian_tag == _ENDIAN_CONSTANT:
        endian = "little"
    elif endian_tag == _REVERSE_ENDIAN:
        endian = "big"
        warn("big-endian DEX; fields read little-endian may be wrong")
    else:
        endian = "unknown"
        warn(f"unexpected endian_tag 0x{endian_tag:08x}")

    string_ids_size = header["string_ids_size"]
    string_ids_off = header["string_ids_off"]
    start = max(0, int(offset))
    window = max(1, min(int(limit), 5000))
    strings: list[str] = []
    if string_ids_size and string_ids_off:
        upper = min(string_ids_size, start + window)
        for index in range(start, upper):
            entry = string_ids_off + index * 4
            if entry + 4 > len(data):
                warn(f"string-id entry {index} is past end of file")
                break
            string_off = _u32(data, entry)
            if string_off >= len(data):
                warn(f"string {index} offset out of bounds")
                continue
            try:
                strings.append(_read_string(data, string_off))
            except DexParseError:
                warn(f"string {index} is truncated")

    return {
        "version": version,
        "checksum": f"0x{checksum:08x}",
        "signature": signature,
        "file_size": header["file_size"],
        "actual_size": len(data),
        "header_size": header["header_size"],
        "endian": endian,
        "map_off": header["map_off"],
        "data_size": header["data_size"],
        "counts": {
            "strings": string_ids_size,
            "types": header["type_ids_size"],
            "protos": header["proto_ids_size"],
            "fields": header["field_ids_size"],
            "methods": header["method_ids_size"],
            "classes": header["class_defs_size"],
        },
        "strings": strings,
        "strings_count": len(strings),
        "strings_total": string_ids_size,
        "offset": start,
        "limit": window,
        "has_more": start + len(strings) < string_ids_size,
        "warnings": warnings,
    }


def list_dex_classes(data: bytes, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """A bounded, paginated page of the class-definition table.

    Raises DexParseError when the bytes are not a Dalvik executable. Each
    class_def_item is a fixed 32-byte record; this resolves the class's own type
    descriptor, its superclass descriptor (NO_INDEX -> null, as for
    java.lang.Object), its named access flags and its source file, every index
    bounds-checked so a corrupt entry yields a warning and a partial row rather
    than an exception.
    """
    version, _checksum, _signature, header = _read_header(data)

    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    total = header["class_defs_size"]
    class_defs_off = header["class_defs_off"]
    start = max(0, int(offset))
    window = max(1, min(int(limit), 1000))
    classes: list[JsonObject] = []
    if total and class_defs_off:
        upper = min(total, start + window)
        for index in range(start, upper):
            base = class_defs_off + index * _CLASS_DEF_SIZE
            if base + _CLASS_DEF_SIZE > len(data):
                warn(f"class_def {index} is past end of file")
                break
            class_idx, access, super_idx, _iface, source_idx, _ann, _cdata, _static = (
                struct.unpack_from("<8I", data, base)
            )
            descriptor = _type_descriptor(data, header, class_idx)
            if descriptor is None:
                warn(f"class_def {index} class type out of bounds")
            superclass = _type_descriptor(data, header, super_idx)
            source_file = _string_by_index(data, header, source_idx)
            classes.append(
                {
                    "descriptor": descriptor or "",
                    "name": _dotted(descriptor),
                    "superclass": superclass,
                    "access_flags": _decode_class_flags(access),
                    "access_flags_raw": access,
                    "source_file": source_file,
                }
            )

    return {
        "version": version,
        "classes": classes,
        "classes_count": len(classes),
        "classes_total": total,
        "offset": start,
        "limit": window,
        "has_more": start + len(classes) < total,
        "warnings": warnings,
    }
