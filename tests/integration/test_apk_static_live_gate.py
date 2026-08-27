"""APK static analysis proven against real androguard, not just degradation.

``test_android_re_gate.py`` builds a deliberately *invalid* APK (its manifest is
not real AXML) and only asserts that every reader degrades to a clean envelope.
That never exercises the happy path, so a version-drift bug in how the
``ApkClient`` calls androguard 4.x -- the same class of break that silently
disabled ``frida.memory.read`` -- would pass every test.

This gate builds a genuinely parseable APK entirely in-process: a hand-encoded
binary ``AndroidManifest.xml`` (AXML) with a package, versions, a uses-sdk, a
permission and an activity, plus a minimal-but-valid empty ``classes.dex``. It
then drives the real service entry points an agent uses and asserts the decoded
values, so the Android static line is proven end to end. skip != pass when
androguard is absent; no external tool or device is required.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.core.service import AnalysisService

_NO = 0xFFFFFFFF
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_PACKAGE = "com.example.headless"
_PERMISSION = "android.permission.INTERNET"

_STRINGS = [
    "android",
    _ANDROID_URI,
    "package",
    "versionCode",
    "versionName",
    "name",
    "minSdkVersion",
    "targetSdkVersion",
    "manifest",
    "uses-sdk",
    "uses-permission",
    "application",
    "activity",
    _PACKAGE,
    "1.4",
    _PERMISSION,
    ".MainActivity",
]
_IDX = {text: index for index, text in enumerate(_STRINGS)}


def _s(text: str) -> int:
    return _IDX[text]


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
    out += struct.pack("<IIII", count, 0, 0, strings_start)  # flags=0 => UTF-16
    out += struct.pack("<I", 0)
    for off in offsets:
        out += struct.pack("<I", off)
    out += data
    return bytes(out)


def _start_ns(prefix: int, uri: int) -> bytes:
    body = struct.pack("<IIII", 1, _NO, prefix, uri)
    return struct.pack("<HHI", 0x0100, 16, 8 + len(body)) + body


def _end_ns(prefix: int, uri: int) -> bytes:
    body = struct.pack("<IIII", 1, _NO, prefix, uri)
    return struct.pack("<HHI", 0x0101, 16, 8 + len(body)) + body


def _start_el(name: int, attrs: list[tuple[int, int, int, int, int]]) -> bytes:
    body = bytearray()
    body += struct.pack("<II", 1, _NO)
    body += struct.pack("<II", _NO, name)
    body += struct.pack("<HHH", 20, 20, len(attrs))
    body += struct.pack("<HHH", 0, 0, 0)
    for a_ns, a_name, a_raw, a_type, a_data in attrs:
        body += struct.pack("<III", a_ns, a_name, a_raw)
        body += struct.pack("<HBBI", 8, 0, a_type, a_data)
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + bytes(body)


def _end_el(name: int) -> bytes:
    body = struct.pack("<IIII", 1, _NO, _NO, name)
    return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body


def _build_manifest_axml() -> bytes:
    uri = _s(_ANDROID_URI)
    chunks = [
        _start_ns(_s("android"), uri),
        _start_el(
            _s("manifest"),
            [
                (_NO, _s("package"), _s(_PACKAGE), _TYPE_STRING, _s(_PACKAGE)),
                (uri, _s("versionCode"), _NO, _TYPE_INT_DEC, 42),
                (uri, _s("versionName"), _s("1.4"), _TYPE_STRING, _s("1.4")),
            ],
        ),
        _start_el(
            _s("uses-sdk"),
            [
                (uri, _s("minSdkVersion"), _NO, _TYPE_INT_DEC, 21),
                (uri, _s("targetSdkVersion"), _NO, _TYPE_INT_DEC, 33),
            ],
        ),
        _end_el(_s("uses-sdk")),
        _start_el(
            _s("uses-permission"),
            [(uri, _s("name"), _s(_PERMISSION), _TYPE_STRING, _s(_PERMISSION))],
        ),
        _end_el(_s("uses-permission")),
        _start_el(_s("application"), []),
        _start_el(
            _s("activity"),
            [(uri, _s("name"), _s(".MainActivity"), _TYPE_STRING, _s(".MainActivity"))],
        ),
        _end_el(_s("activity")),
        _end_el(_s("application")),
        _end_el(_s("manifest")),
        _end_ns(_s("android"), uri),
    ]
    payload = _string_pool(_STRINGS) + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _build_empty_dex() -> bytes:
    """A valid DEX 035 with zero classes: enough to prove the analysis path."""
    header_size = 0x70
    map_off = header_size
    entries = [(0x0000, 1, 0), (0x1000, 1, map_off)]  # HEADER_ITEM, MAP_LIST
    map_list = struct.pack("<I", len(entries))
    for typ, count, off in entries:
        map_list += struct.pack("<HHII", typ, 0, count, off)
    file_size = header_size + len(map_list)

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, header_size)
    struct.pack_into("<I", header, 40, 0x12345678)  # endian tag
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 104, len(map_list))  # data_size
    struct.pack_into("<I", header, 108, map_off)  # data_off

    body = bytearray(bytes(header) + map_list)
    body[12:32] = hashlib.sha1(bytes(body[32:])).digest()  # noqa: S324 - DEX spec uses SHA-1
    struct.pack_into("<I", body, 8, zlib.adler32(bytes(body[12:])) & 0xFFFFFFFF)
    return bytes(body)


def _build_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", _build_manifest_axml())
        archive.writestr("classes.dex", _build_empty_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libhello.so", b"\x7fELFplaceholder")
    return path


@pytest.mark.integration
def test_apk_manifest_readers_decode_real_values(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok and opened.data is not None, opened.error
        assert opened.data["package"] == _PACKAGE
        assert str(opened.data["version_code"]) == "42"
        assert opened.data["version_name"] == "1.4"
        assert str(opened.data["min_sdk"]) == "21"
        assert str(opened.data["target_sdk"]) == "33"
        assert opened.data["permission_count"] == 1
        assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}

        perms = service.apk_permissions(session_id)
        assert perms.ok and perms.data is not None, perms.error
        assert _PERMISSION in perms.data["permissions"]

        comps = service.apk_components(session_id)
        assert comps.ok and comps.data is not None, comps.error
        assert f"{_PACKAGE}.MainActivity" in comps.data["activities"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok and libs.data is not None, libs.error
        assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
        assert libs.data["count"] == 2

        manifest = service.apk_manifest(session_id)
        assert manifest.ok and manifest.data is not None, manifest.error
        assert _PACKAGE in manifest.data["manifest_xml"]

        certs = service.apk_certificates(session_id)
        assert certs.ok and certs.data is not None, certs.error
        assert certs.data["v1_signed"] is False  # unsigned fixture
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_dex_readers_run_against_real_analysis(tmp_path: Path) -> None:
    """DEX-backed readers must run the real androguard analysis, not just skip.

    The fixture DEX is valid but empty, so classes/strings/xrefs return zero and
    a method lookup misses cleanly -- proving the analysis path (AnalyzeAPK,
    get_classes, get_strings, xref walk) works and its empty/absent cases stay
    on the structured contract.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK live gate not run (skip != pass)")
    apk = _build_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id, limit=50)
        assert classes.ok and classes.data is not None, classes.error
        assert classes.data["total"] == 0
        assert classes.data["classes"] == []

        strings = service.apk_strings(session_id, limit=50)
        assert strings.ok and strings.data is not None, strings.error
        assert strings.data["total"] == 0

        xrefs = service.apk_xrefs(session_id, "onCreate")
        assert xrefs.ok and xrefs.data is not None, xrefs.error
        assert xrefs.data["callers"] == []

        missing = service.apk_methods(session_id, "com.example.DoesNotExist")
        assert not missing.ok and missing.error is not None
        assert missing.error.code == "not_found", missing.error
    finally:
        service.close_all()
