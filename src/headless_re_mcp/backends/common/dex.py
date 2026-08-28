"""Pure-stdlib structural reader for a standalone Dalvik executable (.dex).

The apk.* tools drive androguard against an APK *container*; a standalone .dex --
one dropped by malware, loaded dynamically at runtime, or pulled out of an APK --
has no reader here at all, and androguard is not always installed. Yet the DEX
header is a fixed 112-byte record and the string table is a plain offset array
into null-terminated MUTF-8, both exact and well documented. summarize_dex reads
that with the stdlib alone: it validates the magic, reports the version and the
section counts (how many classes, methods, fields, types, strings) and returns a
bounded, paginated slice of the string table -- the class and method names and
string literals that are the first thing an analyst greps.

The header walk is exact; the string table is followed defensively -- an offset
that leaves the file contributes a warning, not an exception -- and every field
and the page are bounded. Strings are decoded best-effort as UTF-8 (DEX stores
MUTF-8, which coincides with UTF-8 for the ASCII identifiers that dominate a
class table); a byte that will not decode becomes a replacement char.
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

# One returned string, and the bytes scanned to find its terminator, are bounded
# so a pathological table cannot inflate a reply. Real identifiers sit far below.
_MAX_STRING = 4096
_MAX_STRING_SCAN = 1 << 16
_MAX_WARNINGS = 32


class DexParseError(ValueError):
    """Bytes that are not a Dalvik executable.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name. Raised only for the
    header; a bad string offset is a warning, not a failure.
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


def summarize_dex(data: bytes, *, offset: int = 0, limit: int = 200) -> JsonObject:
    """Structural summary of a .dex plus a bounded page of its string table.

    Raises DexParseError when the bytes are not a Dalvik executable (bad magic
    or a header that does not fit). The section counts come straight from the
    fixed header; the string page is materialised by following the string-id
    offset array, each entry bounds-checked so a corrupt offset is skipped with
    a warning rather than raising.
    """
    if len(data) < _HEADER_SIZE:
        raise DexParseError("not a DEX file: shorter than a DEX header")
    if data[0:4] != _DEX_MAGIC or data[7] != 0:
        raise DexParseError("not a DEX file: missing the dex\\n magic")
    version = data[4:7].decode("ascii", errors="replace")
    checksum = struct.unpack_from("<I", data, 0x08)[0]
    signature = data[0x0C:0x20].hex()

    (
        file_size,
        header_size,
        endian_tag,
        _link_size,
        _link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        _type_ids_off,
        proto_ids_size,
        _proto_ids_off,
        field_ids_size,
        _field_ids_off,
        method_ids_size,
        _method_ids_off,
        class_defs_size,
        _class_defs_off,
        data_size,
        _data_off,
    ) = struct.unpack_from("<20I", data, 0x20)

    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    if endian_tag == _ENDIAN_CONSTANT:
        endian = "little"
    elif endian_tag == _REVERSE_ENDIAN:
        endian = "big"
        warn("big-endian DEX; fields read little-endian may be wrong")
    else:
        endian = "unknown"
        warn(f"unexpected endian_tag 0x{endian_tag:08x}")

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
            (string_off,) = struct.unpack_from("<I", data, entry)
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
        "file_size": file_size,
        "actual_size": len(data),
        "header_size": header_size,
        "endian": endian,
        "map_off": map_off,
        "data_size": data_size,
        "counts": {
            "strings": string_ids_size,
            "types": type_ids_size,
            "protos": proto_ids_size,
            "fields": field_ids_size,
            "methods": method_ids_size,
            "classes": class_defs_size,
        },
        "strings": strings,
        "strings_count": len(strings),
        "strings_total": string_ids_size,
        "offset": start,
        "limit": window,
        "has_more": start + len(strings) < string_ids_size,
        "warnings": warnings,
    }
