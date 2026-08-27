"""The no-androguard package sniffer must not mistake the android schema URI.

``_apk_package_name`` is the lightweight package-id extractor the ADB backend
uses (install/launch verification) so it need not pull androguard in. Every
manifest string pool holds the android namespace URI
``http://schemas.android.com/apk/res/android``; its ``schemas.android.com``
fragment matches the package shape. When the real package value sits past the
400-char scan window, the full-blob fallback used to return that fragment,
so install/launch verified against the wrong package. These tests pin the fix
using real binary AXML built in-process.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from headless_re_mcp.backends.adb.client import _apk_package_name

_NO = 0xFFFFFFFF
_TYPE_STRING = 0x03
_ANDROID_URI = "http://schemas.android.com/apk/res/android"


def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = bytearray()
    for text in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    count = len(strings)
    strings_start = 28 + 4 * count
    out = bytearray()
    out += struct.pack("<HHI", 0x0001, 28, strings_start + len(data))
    out += struct.pack("<IIII", count, 0, 0, strings_start)
    out += struct.pack("<I", 0)
    for off in offsets:
        out += struct.pack("<I", off)
    return bytes(out) + bytes(data)


def _chunk(chunk_type: int, body: bytes) -> bytes:
    return struct.pack("<HHI", chunk_type, 16, 8 + len(body)) + body


def _build_axml(package: str, *, filler: int = 0) -> bytes:
    strings = ["android", _ANDROID_URI, "package"]
    strings += [f"filler{i:03d}WithSomePaddingText" for i in range(filler)]
    strings += ["manifest", package]
    idx = {text: i for i, text in enumerate(strings)}
    uri = idx[_ANDROID_URI]

    start_ns = _chunk(0x0100, struct.pack("<IIII", 1, _NO, idx["android"], uri))
    end_ns = _chunk(0x0101, struct.pack("<IIII", 1, _NO, idx["android"], uri))

    attr = struct.pack("<III", _NO, idx["package"], idx[package])
    attr += struct.pack("<HBBI", 8, 0, _TYPE_STRING, idx[package])
    start_body = struct.pack("<IIII", 1, _NO, _NO, idx["manifest"])
    start_body += struct.pack("<HHH", 20, 20, 1) + struct.pack("<HHH", 0, 0, 0) + attr
    start_el = _chunk(0x0102, start_body)
    end_el = _chunk(0x0103, struct.pack("<IIII", 1, _NO, _NO, idx["manifest"]))

    payload = _string_pool(strings) + start_ns + start_el + end_el + end_ns
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _apk_with_manifest(path: Path, axml: bytes) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", axml)
    return path


def test_package_recovered_when_value_is_far_from_marker(tmp_path: Path) -> None:
    # 30 filler strings push the real package past the 400-char window, so the
    # full-blob fallback runs -- exactly where schemas.android.com used to win.
    apk = _apk_with_manifest(
        tmp_path / "far.apk", _build_axml("com.realapp.product.flavor", filler=30)
    )
    assert _apk_package_name(apk) == "com.realapp.product.flavor"


def test_package_recovered_from_small_manifest(tmp_path: Path) -> None:
    apk = _apk_with_manifest(tmp_path / "near.apk", _build_axml("com.example.headless"))
    assert _apk_package_name(apk) == "com.example.headless"


def test_schemas_android_com_is_never_returned(tmp_path: Path) -> None:
    # Even with no user package present at all, the schema host must not leak
    # out as a package guess.
    strings = ["android", _ANDROID_URI, "package", "manifest"]
    idx = {text: i for i, text in enumerate(strings)}
    uri = idx[_ANDROID_URI]
    start_ns = _chunk(0x0100, struct.pack("<IIII", 1, _NO, idx["android"], uri))
    end_ns = _chunk(0x0101, struct.pack("<IIII", 1, _NO, idx["android"], uri))
    start_body = struct.pack("<IIII", 1, _NO, _NO, idx["manifest"])
    start_body += struct.pack("<HHH", 20, 20, 0) + struct.pack("<HHH", 0, 0, 0)
    start_el = _chunk(0x0102, start_body)
    end_el = _chunk(0x0103, struct.pack("<IIII", 1, _NO, _NO, idx["manifest"]))
    payload = _string_pool(strings) + start_ns + start_el + end_el + end_ns
    axml = struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload

    apk = _apk_with_manifest(tmp_path / "noise.apk", axml)
    assert _apk_package_name(apk) != "schemas.android.com"


def test_missing_manifest_returns_none(tmp_path: Path) -> None:
    apk = tmp_path / "empty.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00")
    assert _apk_package_name(apk) is None
