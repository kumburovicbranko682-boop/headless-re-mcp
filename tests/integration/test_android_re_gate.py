"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "hello_world.apk"
# The committed fixture's known-good facts; the gate asserts these come back so
# the androguard/jadx happy path is exercised, not just the degradation path.
_FIXTURE_PACKAGE = "com.example.hello"
_FIXTURE_ACTIVITY = "com.example.hello.MainActivity"
_FIXTURE_MARKER = "headless-re-mcp-marker-7f3a"


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
        # answer with a structured envelope rather than raising. Whether
        # androguard is installed (a manifest it cannot parse -> backend_error)
        # or absent (capability_unavailable), the one code it must never be is
        # internal_error: that means a raw exception escaped the backend and got
        # filed as a false incident, which is what an unguarded version getter
        # did until apk_open wrapped it.
        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        assert opened.ok or opened.error is not None
        if not opened.ok:
            assert opened.error is not None
            assert opened.error.code != "internal_error", opened.error.message

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


@pytest.mark.integration
def test_android_apk_static_happy_path_when_androguard_present() -> None:
    """androguard parses the real fixture end to end, not just degrades.

    The other test drives a synthetic (invalid) archive, so androguard's success
    path -- manifest facts, components, and DEX classes/methods/strings -- never
    runs there. This one opens the committed valid APK and asserts its known
    contents, so a regression that broke real parsing would fail rather than
    silently keep passing on the degradation path.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static happy path not run (skip != pass)")
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_APK_FIXTURE), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _FIXTURE_PACKAGE
        assert opened.data["main_activity"] == _FIXTURE_ACTIVITY

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == _FIXTURE_PACKAGE

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert "android.permission.INTERNET" in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert _FIXTURE_ACTIVITY in components.data["activities"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert any("MainActivity" in name for name in classes.data["classes"])

        methods = service.apk_methods(session_id, _FIXTURE_ACTIVITY)
        assert methods.ok, methods.error
        assert "secretMarker" in {m["name"] for m in methods.data["methods"]}

        strings = service.apk_strings(session_id, limit=200)
        assert strings.ok, strings.error
        assert _FIXTURE_MARKER in strings.data["strings"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_jadx_decompile_when_configured() -> None:
    """jadx decompiles the fixture's one class back to source with its marker."""
    service = AnalysisService()
    try:
        if not JadxClient(getattr(service.settings, "jadx", None)).available:
            pytest.skip("jadx not configured — decompile gate not run (skip != pass)")
        assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"
        created = service.create_session(str(_APK_FIXTURE), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.apk_decompile(session_id, _FIXTURE_ACTIVITY, timeout=180.0)
        assert result.ok, result.error
        assert _FIXTURE_MARKER in result.data["source"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apktool_decode_repack_roundtrip_when_configured() -> None:
    """apktool disassembles the fixture to smali and rebuilds it.

    This is the Android modification line (decode -> edit -> build), which only
    mocked degradation tests cover otherwise. Driving the real round trip on the
    committed valid APK means a regression in argument construction or output
    parsing fails here instead of passing on a mock. Signing needs apksigner
    (Android build-tools) and stays covered by the degradation unit test.
    """
    service = AnalysisService()
    try:
        if not ApktoolClient(getattr(service.settings, "apktool", None)).available:
            pytest.skip("apktool not configured — decode/repack gate not run (skip != pass)")
        assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"
        created = service.create_session(str(_APK_FIXTURE), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=180.0)
        assert decoded.ok, decoded.error
        assert decoded.data["smali_dirs"], "apktool produced no smali directory"
        manifest = Path(decoded.data["manifest"])
        assert manifest.is_file()
        # apktool decodes the binary AXML back to text that names the package.
        assert _FIXTURE_PACKAGE in manifest.read_text(encoding="utf-8", errors="replace")

        repacked = service.apk_repack(session_id, timeout=180.0)
        assert repacked.ok, repacked.error
        assert repacked.data["signed"] is False
        assert Path(repacked.data["apk"]).is_file()
    finally:
        service.close_all()
