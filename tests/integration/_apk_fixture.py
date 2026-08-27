"""Build a genuinely androguard-parseable APK from scratch, with no SDK.

The Android RE gate otherwise only ever hands androguard a deliberately invalid
archive, so it proves the *degradation* path but never that the adapter reads a
real manifest -- exactly where androguard's version-to-version API drift (the
renamed ``get_androidversion_*`` accessors, permission/component getters) would
break the APK backend silently. Compiling a real ``.dex`` needs the Android
build tools, but the manifest-level surface (package, version, permissions,
components, native ABIs) only needs a valid ZIP plus a valid *binary* XML
(AXML) manifest, and that we can encode directly.

The encoder writes the AOSP resource-chunk format androidguard's ``AXMLParser``
consumes: a UTF-16 string pool, a resource map that maps the framework
attribute-name strings to their public resource ids (so ``android:name`` and
friends resolve), then the XML node stream. It is intentionally minimal -- just
enough of the format for androguard 4.x to reconstruct the element tree.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

_ANDROID_URI = "http://schemas.android.com/apk/res/android"

# Public resource ids for the framework attributes we emit. androguard maps the
# attribute-name string index through the resource map to these ids and looks up
# the human-readable "android:<name>" from its built-in table.
_RES_VERSION_CODE = 0x0101021B
_RES_VERSION_NAME = 0x0101021C
_RES_NAME = 0x01010003

# String pool. The first three entries are the framework attribute names and get
# resource-map ids at the same indices; the rest are plain strings (id 0).
_STRINGS: tuple[str, ...] = (
    "versionCode",  # 0
    "versionName",  # 1
    "name",         # 2
    "android",      # 3  namespace prefix
    _ANDROID_URI,   # 4  namespace uri
    "package",      # 5  plain (string-resolved) attribute
    "com.example.hello",  # 6
    "1.0",          # 7
    "manifest",     # 8
    "uses-permission",  # 9
    "android.permission.INTERNET",  # 10
    "android.permission.ACCESS_NETWORK_STATE",  # 11
    "application",  # 12
    "activity",     # 13
    "com.example.hello.MainActivity",  # 14
    "intent-filter",  # 15
    "action",       # 16
    "android.intent.action.MAIN",  # 17
    "category",     # 18
    "android.intent.category.LAUNCHER",  # 19
    "service",      # 20
    "com.example.hello.SyncService",  # 21
    "receiver",     # 22
    "com.example.hello.BootReceiver",  # 23
    "provider",     # 24
    "com.example.hello.FileProvider",  # 25
)
_RESOURCE_MAP: tuple[int, ...] = (_RES_VERSION_CODE, _RES_VERSION_NAME, _RES_NAME)
_S = {name: index for index, name in enumerate(_STRINGS)}

_NO_REF = 0xFFFFFFFF
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _string_pool() -> bytes:
    data = b""
    offsets: list[int] = []
    for text in _STRINGS:
        offsets.append(len(data))
        data += _u16(len(text)) + text.encode("utf-16-le") + _u16(0)
    while len(data) % 4:
        data += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(_STRINGS)
    chunk_size = strings_start + len(data)
    out = _u16(0x0001) + _u16(header_size) + _u32(chunk_size)
    out += _u32(len(_STRINGS)) + _u32(0) + _u32(0)  # count, styleCount, flags(UTF-16)
    out += _u32(strings_start) + _u32(0)  # stringsStart, stylesStart
    for offset in offsets:
        out += _u32(offset)
    out += data
    return out


def _resource_map() -> bytes:
    out = _u16(0x0180) + _u16(8) + _u32(8 + 4 * len(_RESOURCE_MAP))
    for resource_id in _RESOURCE_MAP:
        out += _u32(resource_id)
    return out


def _start_ns() -> bytes:
    return (
        _u16(0x0100) + _u16(16) + _u32(24) + _u32(_NO_REF) + _u32(_NO_REF)
        + _u32(_S["android"]) + _u32(_S[_ANDROID_URI])
    )


def _end_ns() -> bytes:
    return (
        _u16(0x0101) + _u16(16) + _u32(24) + _u32(_NO_REF) + _u32(_NO_REF)
        + _u32(_S["android"]) + _u32(_S[_ANDROID_URI])
    )


def _attr(*, ns: int, name: int, raw: int, dtype: int, data: int) -> bytes:
    return _u32(ns) + _u32(name) + _u32(raw) + _u16(8) + bytes([0, dtype]) + _u32(data)


def _android_name(value: str) -> bytes:
    """An ``android:name="value"`` attribute (the common case)."""
    return _attr(
        ns=_S[_ANDROID_URI], name=_S["name"], raw=_S[value],
        dtype=_TYPE_STRING, data=_S[value],
    )


def _start(tag: str, attrs: tuple[bytes, ...] = ()) -> bytes:
    body = _u32(_NO_REF) + _u32(_S[tag])
    body += _u16(20) + _u16(20) + _u16(len(attrs)) + _u16(0) + _u16(0) + _u16(0)
    body += b"".join(attrs)
    header = _u16(0x0102) + _u16(16) + _u32(16 + len(body))
    return header + _u32(_NO_REF) + _u32(_NO_REF) + body


def _end(tag: str) -> bytes:
    header = _u16(0x0103) + _u16(16) + _u32(24)
    return header + _u32(_NO_REF) + _u32(_NO_REF) + _u32(_NO_REF) + _u32(_S[tag])


def _leaf(tag: str, name_value: str) -> bytes:
    """A self-closing element carrying a single ``android:name``."""
    return _start(tag, (_android_name(name_value),)) + _end(tag)


def build_manifest_axml() -> bytes:
    """Encode the binary AndroidManifest.xml for the fixture app."""
    package = _attr(
        ns=_NO_REF, name=_S["package"], raw=_S["com.example.hello"],
        dtype=_TYPE_STRING, data=_S["com.example.hello"],
    )
    version_code = _attr(
        ns=_S[_ANDROID_URI], name=_S["versionCode"], raw=_NO_REF,
        dtype=_TYPE_INT_DEC, data=1,
    )
    version_name = _attr(
        ns=_S[_ANDROID_URI], name=_S["versionName"], raw=_S["1.0"],
        dtype=_TYPE_STRING, data=_S["1.0"],
    )
    nodes = _start_ns()
    nodes += _start("manifest", (package, version_code, version_name))
    nodes += _leaf("uses-permission", "android.permission.INTERNET")
    nodes += _leaf("uses-permission", "android.permission.ACCESS_NETWORK_STATE")
    nodes += _start("application")
    nodes += _start("activity", (_android_name("com.example.hello.MainActivity"),))
    nodes += _start("intent-filter")
    nodes += _leaf("action", "android.intent.action.MAIN")
    nodes += _leaf("category", "android.intent.category.LAUNCHER")
    nodes += _end("intent-filter")
    nodes += _end("activity")
    nodes += _leaf("service", "com.example.hello.SyncService")
    nodes += _leaf("receiver", "com.example.hello.BootReceiver")
    nodes += _leaf("provider", "com.example.hello.FileProvider")
    nodes += _end("application")
    nodes += _end("manifest")
    nodes += _end_ns()

    body = _string_pool() + _resource_map() + nodes
    return _u16(0x0003) + _u16(8) + _u32(8 + len(body)) + body


#: Facts the fixture manifest encodes, for the gate to assert against.
EXPECTED = {
    "package": "com.example.hello",
    "version_name": "1.0",
    "version_code": "1",
    "permissions": {"android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"},
    "main_activity": "com.example.hello.MainActivity",
    "activities": {"com.example.hello.MainActivity"},
    "services": {"com.example.hello.SyncService"},
    "receivers": {"com.example.hello.BootReceiver"},
    "providers": {"com.example.hello.FileProvider"},
    "native_abis": {"arm64-v8a", "x86_64"},
}


def build_valid_apk(path: Path) -> Path:
    """Write an APK androguard parses to :data:`EXPECTED` at ``path``.

    The manifest is real binary AXML; the ``.dex`` is a placeholder because the
    manifest surface never decodes it (the DEX-dependent tools have their own
    Windows-independent unit coverage). Native libs and a v1 signature file make
    the ABI and signing facts real ZIP entries.
    """
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", build_manifest_axml())
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
    return path
