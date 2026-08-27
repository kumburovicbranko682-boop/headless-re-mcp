"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _build_synthetic_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        # Minimal (not AXML-valid) manifest is enough for stdlib classification.
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


# --- Minimal binary AndroidManifest (AXML) builder -------------------------
#
# androguard parses Android's binary XML, not text, so proving its happy path
# needs a manifest in that format. The synthetic APK above is deliberately
# malformed to exercise degradation; the helpers below build the smallest
# *valid* manifest androguard fully parses -- a package, one android:-namespaced
# permission, and one activity -- so the Android static tools can be tested for
# real without committing a binary blob or depending on the Android SDK. The
# chunk layout follows frameworks/base ResourceTypes.h: every chunk is
# {uint16 type, uint16 header_size, uint32 size} followed by its body.
_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_RES_ANDROID_NAME = 0x01010003  # framework resource id of the android:name attr
_NO_REF = 0xFFFFFFFF
_TYPE_STRING = 0x03


def _axml_string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = bytearray()
    for text in strings:
        offsets.append(len(data))
        # UTF-16: char count, the code units, then a null terminator.
        data += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    chunk = bytearray()
    chunk += struct.pack("<HHI", 0x0001, header_size, strings_start + len(data))
    chunk += struct.pack("<IIII", len(strings), 0, 0, strings_start)
    chunk += struct.pack("<I", 0)  # styles start (none)
    for offset in offsets:
        chunk += struct.pack("<I", offset)
    chunk += data
    return bytes(chunk)


def _axml_resource_map(ids: list[int]) -> bytes:
    body = b"".join(struct.pack("<I", value) for value in ids)
    return struct.pack("<HHI", 0x0180, 8, 8 + len(body)) + body


def _axml_chunk(chunk_type: int, body: bytes) -> bytes:
    return struct.pack("<HHI", chunk_type, 16, 8 + len(body)) + body


def _axml_namespace(chunk_type: int, prefix: int, uri: int) -> bytes:
    return _axml_chunk(chunk_type, struct.pack("<IIII", 1, _NO_REF, prefix, uri))


def _axml_attribute(namespace: int, name: int, value: int) -> bytes:
    # Raw value index, then the typed value {size, res0, type, data}.
    return struct.pack("<III", namespace, name, value) + struct.pack(
        "<HBBI", 8, 0, _TYPE_STRING, value
    )


def _axml_start(name: int, attributes: list[bytes]) -> bytes:
    body = bytearray()
    body += struct.pack("<IIII", 1, _NO_REF, _NO_REF, name)
    body += struct.pack("<HHH", 20, 20, len(attributes))  # attr start, size, count
    body += struct.pack("<HHH", 0, 0, 0)  # id / class / style attr (none)
    for attribute in attributes:
        body += attribute
    return _axml_chunk(0x0102, bytes(body))


def _axml_end(name: int) -> bytes:
    return _axml_chunk(0x0103, struct.pack("<IIII", 1, _NO_REF, _NO_REF, name))


def _axml_manifest(package: str, permission: str, activity: str) -> bytes:
    # Resource-mapped attribute names must come first so a pool index lines up
    # with its resource map entry; android:name is the only one used here.
    strings = [
        "name",
        "manifest",
        "package",
        package,
        "uses-permission",
        permission,
        "application",
        "activity",
        activity,
        "android",
        _ANDROID_URI,
    ]
    at = {text: index for index, text in enumerate(strings)}
    chunks = [
        _axml_string_pool(strings),
        _axml_resource_map([_RES_ANDROID_NAME]),
        _axml_namespace(0x0100, at["android"], at[_ANDROID_URI]),
        _axml_start(at["manifest"], [_axml_attribute(_NO_REF, at["package"], at[package])]),
        _axml_start(
            at["uses-permission"],
            [_axml_attribute(at[_ANDROID_URI], at["name"], at[permission])],
        ),
        _axml_end(at["uses-permission"]),
        _axml_start(at["application"], []),
        _axml_start(
            at["activity"],
            [_axml_attribute(at[_ANDROID_URI], at["name"], at[activity])],
        ),
        _axml_end(at["activity"]),
        _axml_end(at["application"]),
        _axml_end(at["manifest"]),
        _axml_namespace(0x0101, at["android"], at[_ANDROID_URI]),
    ]
    payload = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _build_valid_apk(path: Path) -> Path:
    manifest = _axml_manifest(
        "com.example.gate",
        "android.permission.INTERNET",
        "com.example.gate.MainActivity",
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
    return path


@pytest.mark.integration
def test_android_session_classification_and_metadata(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")

    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True

        session_id = session["id"]

        # androguard opens a real APK; on the synthetic archive it must still
        # answer with a structured envelope rather than raising.
        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        assert opened.ok or opened.error is not None

        # Device enumeration degrades cleanly when adbutils / adb is absent.
        listed = service.device_list()
        assert isinstance(listed.ok, bool)
        assert listed.ok or listed.error is not None

        # Frida device enumeration returns an envelope (frida may be present).
        devices = service.frida_devices()
        assert isinstance(devices.ok, bool)
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_static_tools_parse_a_valid_apk(tmp_path: Path) -> None:
    """androguard's happy path: a valid APK yields real package/perm/component facts.

    Every other Android assertion here checks graceful degradation on a
    malformed archive; this one proves the static tools actually parse a
    well-formed APK, so the line is exercised end to end rather than only in its
    failure mode. Skips honestly when androguard is absent (skip != pass).
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — Android static Gate not run (skip != pass)")

    apk = _build_valid_apk(tmp_path / "valid.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == "com.example.gate"
        assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert opened.data["permission_count"] >= 1

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert "com.example.gate" in manifest.data["manifest_xml"]
        assert "uses-permission" in manifest.data["manifest_xml"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert "android.permission.INTERNET" in permissions.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert "com.example.gate.MainActivity" in components.data["activities"]

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert native.data["count"] == 2
        assert set(native.data["abis"]) == {"arm64-v8a", "x86_64"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_pe_tool_rejects_apk_session(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        # A PE-only tool must refuse an APK session with target_mismatch, not crash.
        opened = service.open_static(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code in {"target_mismatch", "invalid_request", "backend_unavailable"}
    finally:
        service.close_all()
