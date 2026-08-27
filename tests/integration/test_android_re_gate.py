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

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_ANDROID_URI = "http://schemas.android.com/apk/res/android"
_APK_PACKAGE = "com.example.gate"
_APK_PERMISSION = "android.permission.INTERNET"
_APK_ACTIVITY = "com.example.gate.MainActivity"


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


# --- Minimal *valid* binary AndroidManifest (AXML) -------------------------
#
# The synthetic APK above is enough for stdlib classification, but its manifest
# is not real AXML, so androguard cannot read a single fact from it. To give the
# androguard static line genuine live coverage we need a manifest androguard
# actually parses -- and building one normally needs the Android SDK (aapt).
# Instead we hand-encode the AXML binary format directly: it is self-contained
# (stdlib struct + zipfile), so the gate builds a real, parseable APK in CI
# without any Android toolchain. Attribute names are encoded as literal strings
# (e.g. "name") rather than the resource-id form aapt emits, which is exactly
# the form androguard resolves by (namespace, name) without a resource map.
_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_RES_XML_START_NS = 0x0100
_RES_XML_END_NS = 0x0101
_RES_XML_START_ELEM = 0x0102
_RES_XML_END_ELEM = 0x0103
_UTF8_FLAG = 0x00000100
_TYPE_STRING = 0x03
_NIL = 0xFFFFFFFF


class _AxmlStrings:
    """Interning UTF-8 string pool for the AXML chunk."""

    def __init__(self) -> None:
        self._list: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self._list)
            self._list.append(value)
        return self._index[value]

    def encode(self) -> bytes:
        offsets: list[int] = []
        data = bytearray()
        for value in self._list:
            offsets.append(len(data))
            raw = value.encode("utf-8")
            # Single-byte lengths: every string here is short ASCII (< 0x80).
            assert len(value) < 0x80 and len(raw) < 0x80
            data.append(len(value))
            data.append(len(raw))
            data += raw
            data.append(0x00)
        while len(data) % 4 != 0:
            data.append(0x00)
        header_size = 28
        strings_start = header_size + 4 * len(self._list)
        chunk_size = strings_start + len(data)
        out = bytearray()
        out += struct.pack("<HHI", _RES_STRING_POOL, header_size, chunk_size)
        out += struct.pack("<III", len(self._list), 0, _UTF8_FLAG)
        out += struct.pack("<II", strings_start, 0)
        for offset in offsets:
            out += struct.pack("<I", offset)
        out += data
        return bytes(out)


def _axml_node_header(node_type: int, size: int) -> bytes:
    return struct.pack("<HHIII", node_type, 16, size, 1, 0xFFFFFFFF)


def _axml_start_elem(name: int, attrs: list[tuple[int, int, int]]) -> bytes:
    size = 16 + 20 + 20 * len(attrs)
    out = bytearray()
    out += _axml_node_header(_RES_XML_START_ELEM, size)
    out += struct.pack("<II", _NIL, name)  # element namespace, name
    out += struct.pack("<HHH", 20, 20, len(attrs))  # attr start, size, count
    out += struct.pack("<HHH", 0, 0, 0)  # id, class, style index (none)
    for a_ns, a_name, a_value in attrs:
        out += struct.pack("<III", a_ns, a_name, a_value)
        out += struct.pack("<HBBI", 8, 0, _TYPE_STRING, a_value)
    return bytes(out)


def _axml_end_elem(name: int) -> bytes:
    return _axml_node_header(_RES_XML_END_ELEM, 24) + struct.pack("<II", _NIL, name)


def _build_axml_manifest() -> bytes:
    s = _AxmlStrings()
    i_android = s.add("android")
    i_uri = s.add(_ANDROID_URI)
    i_package = s.add("package")
    i_pkg = s.add(_APK_PACKAGE)
    i_manifest = s.add("manifest")
    i_uses_perm = s.add("uses-permission")
    i_name = s.add("name")
    i_perm = s.add(_APK_PERMISSION)
    i_application = s.add("application")
    i_activity = s.add("activity")
    i_activity_val = s.add(_APK_ACTIVITY)
    i_intent = s.add("intent-filter")
    i_action = s.add("action")
    i_action_val = s.add("android.intent.action.MAIN")
    i_category = s.add("category")
    i_category_val = s.add("android.intent.category.LAUNCHER")

    body = bytearray()
    body += _axml_node_header(_RES_XML_START_NS, 24) + struct.pack("<II", i_android, i_uri)
    body += _axml_start_elem(i_manifest, [(_NIL, i_package, i_pkg)])
    body += _axml_start_elem(i_uses_perm, [(i_uri, i_name, i_perm)])
    body += _axml_end_elem(i_uses_perm)
    body += _axml_start_elem(i_application, [])
    body += _axml_start_elem(i_activity, [(i_uri, i_name, i_activity_val)])
    body += _axml_start_elem(i_intent, [])
    body += _axml_start_elem(i_action, [(i_uri, i_name, i_action_val)])
    body += _axml_end_elem(i_action)
    body += _axml_start_elem(i_category, [(i_uri, i_name, i_category_val)])
    body += _axml_end_elem(i_category)
    body += _axml_end_elem(i_intent)
    body += _axml_end_elem(i_activity)
    body += _axml_end_elem(i_application)
    body += _axml_end_elem(i_manifest)
    body += _axml_node_header(_RES_XML_END_NS, 24) + struct.pack("<II", i_android, i_uri)

    pool = _AxmlStrings.encode(s)
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", _RES_XML, 8, total) + pool + bytes(body)


def _build_valid_apk(path: Path) -> Path:
    """A minimal APK androguard fully parses (package/permission/activity)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", _build_axml_manifest())
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60)
        archive.writestr("resources.arsc", b"")
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

        # androguard opens a real APK; on the synthetic archive its manifest is
        # not valid AXML, so apk.open must fail with a *structured* backend_error
        # -- androguard's constructor does not raise but leaves getters that do,
        # which used to fall through to the service's BaseException handler as an
        # internal_error with a logged incident (a bad APK misreported as a
        # server defect).
        opened = service.apk_open(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code == "backend_error"

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
def test_valid_apk_androguard_reads_real_static_facts(tmp_path: Path) -> None:
    """Live androguard coverage: a real, parseable APK, not just degradation.

    Every other Android assertion runs against the synthetic archive whose
    manifest is not valid AXML, so androguard could only ever be exercised on
    its failure path. This builds a genuine APK (hand-encoded binary manifest,
    no Android SDK needed) and asserts androguard extracts the package,
    permission and launcher activity that were actually encoded -- the
    in-process static line proving it works, not merely that it fails cleanly.
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    apk = _build_valid_apk(tmp_path / "valid.apk")
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _APK_PACKAGE
        assert opened.data["main_activity"] == _APK_ACTIVITY
        assert opened.data["permission_count"] >= 1
        assert "arm64-v8a" in opened.data["native_abis"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == _APK_PACKAGE
        assert "uses-permission" in manifest.data["manifest_xml"]

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert _APK_PERMISSION in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert _APK_ACTIVITY in components.data["activities"]
        assert components.data["main_activity"] == _APK_ACTIVITY
    finally:
        service.close_all()


@pytest.mark.integration
def test_malformed_apk_yields_structured_errors_not_incidents(tmp_path: Path) -> None:
    """A malformed APK is bad input, never a server defect.

    androguard is lenient: APK() does not raise on a broken manifest, so every
    apk.* method has to defend its own getters. Any that lets an androguard
    exception escape surfaces as internal_error with a logged incident, telling
    an unattended caller the server is broken when the sample is. Pin that none
    of them do that on the synthetic (invalid-AXML) archive.
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]
        calls = {
            "apk_open": lambda: service.apk_open(session_id),
            "apk_manifest": lambda: service.apk_manifest(session_id),
            "apk_permissions": lambda: service.apk_permissions(session_id),
            "apk_components": lambda: service.apk_components(session_id),
            "apk_native_libs": lambda: service.apk_native_libs(session_id),
            "apk_certificates": lambda: service.apk_certificates(session_id),
        }
        for name, call in calls.items():
            result = call()
            assert isinstance(result.ok, bool), name
            if not result.ok:
                assert result.error is not None, name
                assert result.error.code != "internal_error", (
                    f"{name} reported a malformed APK as a server incident"
                )
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
