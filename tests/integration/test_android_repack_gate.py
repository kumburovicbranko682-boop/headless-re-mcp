"""Android repack/sign gate: patch → rebuild → sign, verified end to end.

The Android RE gate only classifies a synthetic APK, and the decompile gate
proves jadx. Neither touches apktool or apksigner, so the patch-and-repack
workflow -- decode an APK, edit it, rebuild, sign it so it can install -- had no
coverage off Windows, and the unit tests only mock the subprocesses (the same
blind spot that hid two Ghidra bugs). This gate bootstraps a real APK with
apktool, then drives ``apk.decode`` / ``apk.repack`` / ``apk.sign`` through
``AnalysisService`` exactly as an MCP client would: it flips ``android:label``
in the decoded manifest, rebuilds, signs with a throwaway keystore kept inside
the session artifact tree, and re-decodes the signed APK to prove the edit
survived rebuild *and* signing -- not merely that the commands exited zero.

skip != pass: it skips only when apktool, apksigner, or keytool is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.gate">
    <application android:label="Gate"></application>
</manifest>
"""

# A minimal but complete apktool project descriptor. The ``usesFramework`` entry
# is what lets ``android:label`` resolve against the framework; a stripped-down
# yml builds a broken APK that will not decode. The version field is left out on
# purpose so the fixture is not tied to one apktool release.
_APKTOOL_YML = """!!brut.androlib.meta.MetaInfo
isFrameworkApk: false
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '33'
"""


def _bootstrap_base_apk(apktool: Path, work: Path) -> Path | None:
    """Assemble a genuine APK from a minimal project so decode has real input."""
    project = work / "project"
    project.mkdir(parents=True)
    (project / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (project / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    apk = work / "base.apk"
    try:
        subprocess.run(
            [str(apktool), "b", str(project), "-o", str(apk)],
            check=False,
            capture_output=True,
            timeout=300,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    # apktool warns (and can exit non-zero) about the bundled aapt while still
    # writing a usable APK, so trust the artifact on disk rather than the code.
    return apk if apk.is_file() else None


def _make_keystore(keytool: str, keystore: Path) -> bool:
    keystore.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                keytool,
                "-genkeypair",
                "-keystore",
                str(keystore),
                "-storepass",
                "gatepass",
                "-alias",
                "gatekey",
                "-keypass",
                "gatepass",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "365",
                "-dname",
                "CN=Gate",
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return keystore.is_file()


@pytest.mark.integration
def test_apk_patch_repack_and_sign_round_trip(tmp_path: Path) -> None:
    base_settings = Settings.load()
    apktool = base_settings.apktool
    apksigner = base_settings.apksigner
    keytool = shutil.which("keytool")
    if apktool is None or not apktool.is_file():
        pytest.skip("apktool not configured — Android repack Gate not run (skip != pass)")
    if apksigner is None or not apksigner.is_file():
        pytest.skip("apksigner not configured — Android repack Gate not run (skip != pass)")
    if keytool is None:
        pytest.skip("keytool (JDK) not available — Android repack Gate not run (skip != pass)")

    base_apk = _bootstrap_base_apk(apktool, tmp_path / "bootstrap")
    if base_apk is None:
        pytest.skip("apktool could not build a base APK — repack Gate not run (skip != pass)")

    artifact_root = (tmp_path / "artifacts").resolve()
    settings = replace(base_settings, artifact_root=artifact_root)
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(base_apk))
        assert created.ok and created.data is not None, created.error
        assert created.data["session"]["target"] == "apk"
        session_id = created.data["session"]["id"]

        decoded = service.apk_decode(session_id, timeout=300.0)
        assert decoded.ok and decoded.data is not None, decoded.error
        manifest = Path(decoded.data["decoded_dir"]) / "AndroidManifest.xml"
        assert manifest.is_file()
        original = manifest.read_text(encoding="utf-8")
        assert 'android:label="Gate"' in original
        manifest.write_text(
            original.replace('android:label="Gate"', 'android:label="PatchedByGate"'),
            encoding="utf-8",
        )

        repacked = service.apk_repack(session_id, timeout=300.0)
        assert repacked.ok and repacked.data is not None, repacked.error
        assert repacked.data["signed"] is False
        assert int(repacked.data["size"]) > 0

        keystore = artifact_root / "apktool" / session_id / "gate.keystore"
        assert _make_keystore(keytool, keystore), "keytool failed to create the gate keystore"
        signed = service.apk_sign(
            session_id,
            keystore=str(keystore),
            keystore_password="gatepass",
            key_alias="gatekey",
            timeout=300.0,
        )
        assert signed.ok and signed.data is not None, signed.error
        # sign() only returns after apksigner verify succeeds, so a truthy
        # "signed" here means the output APK is genuinely, verifiably signed.
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is False

        # The whole point of repack is carrying an edit through: re-decode the
        # signed APK and confirm the manifest change survived rebuild + signing.
        verify_dir = tmp_path / "verify"
        ApktoolClient(apktool, apksigner).decode(
            Path(signed.data["apk"]), verify_dir, timeout=300.0
        )
        rebuilt_manifest = (verify_dir / "AndroidManifest.xml").read_text(encoding="utf-8")
        assert 'android:label="PatchedByGate"' in rebuilt_manifest
    finally:
        service.close_all()
