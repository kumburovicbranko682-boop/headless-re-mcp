"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

# A text manifest apktool can compile into a real binary AndroidManifest.xml.
# The values below are what the androguard success path must read back.
_REAL_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.gate">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <application android:label="Gate"></application>
</manifest>
"""

_REAL_APKTOOL_YML = """!!brut.androlib.meta.MetaInfo
apkFileName: gate.apk
isFrameworkApk: false
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '33'
usesFramework:
  ids:
  - 1
version: 2.7.0
versionInfo:
  versionCode: '1'
  versionName: '1.0'
"""


def _build_real_apk(tmp_path: Path) -> Path:
    """Compile a real APK from a text manifest, or skip if apktool cannot."""
    apktool = shutil.which("apktool")
    if apktool is None:
        pytest.skip("apktool not installed — cannot compile a real manifest (skip != pass)")
    skeleton = tmp_path / "src"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_REAL_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_REAL_APKTOOL_YML, encoding="utf-8")
    out = tmp_path / "real.apk"
    proc = subprocess.run(
        [apktool, "b", str(skeleton), "-o", str(out)],
        capture_output=True,
        timeout=120,
    )
    if proc.returncode != 0 or not out.is_file():
        pytest.skip(
            f"apktool build failed here — Gate not run (skip != pass): "
            f"{proc.stderr.decode('utf-8', 'replace')[:200]}"
        )
    return out


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
def test_androguard_reads_a_real_compiled_manifest(tmp_path: Path) -> None:
    """The androguard success path must extract the manifest's real values.

    Every other apk test runs on the synthetic archive, whose fake AXML only
    exercises the backend_error path; the contract guard checks the API exists
    but not that it reads correctly. Compile a manifest with known package and
    SDK levels and assert apk.open / apk.manifest return exactly those, so a
    change in how androguard decodes AXML (its 4.x rewrite touched this) fails
    a test instead of silently mis-reporting an app's identity.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — success path not exercised (skip != pass)")
    apk = _build_real_apk(tmp_path)

    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == "com.example.gate"
        assert str(opened.data["min_sdk"]) == "21"
        assert str(opened.data["target_sdk"]) == "33"

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.gate"
        assert "uses-sdk" in manifest.data["manifest_xml"]
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
