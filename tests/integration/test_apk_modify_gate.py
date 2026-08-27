"""Live APK modification gate: apktool build then apksigner sign, no device.

apk.repack drives apktool's ``b`` and apk.sign drives apksigner's sign+verify;
both are JRE CLIs whose flags (apksigner's ``--ks-pass`` / ``--key-pass`` /
``--out``, apktool's ``b -o``) are exactly what a tool bump moves. Neither ran
live before because apksigner refuses an APK whose binary AndroidManifest.xml it
cannot read a minSdkVersion from -- so this compiles a real manifest with
apktool from a text skeleton, then signs the result and lets apksigner verify
it. Skips honestly when apktool, apksigner, or keytool is absent (skip != pass).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.gate">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <application android:label="Gate"></application>
</manifest>
"""

# apktool needs its metadata sidecar to build; the fields below are the stable
# apktool 2.x shape (apkFileName, sdkInfo, usesFramework, versionInfo).
_APKTOOL_YML = """!!brut.androlib.meta.MetaInfo
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


def _tool(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


@pytest.mark.integration
def test_apktool_build_then_apksigner_sign_roundtrip(tmp_path: Path) -> None:
    apktool = _tool("apktool")
    apksigner = _tool("apksigner")
    keytool = _tool("keytool")
    if apktool is None or apksigner is None:
        pytest.skip("apktool/apksigner not installed — APK modify Gate not run (skip != pass)")
    if keytool is None:
        pytest.skip("keytool not installed — cannot mint a signing key (skip != pass)")

    skeleton = tmp_path / "decoded"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")

    client = ApktoolClient(apktool=apktool, apksigner=apksigner)

    # apk.repack: apktool compiles the text manifest into a real binary APK.
    built = client.build(skeleton, tmp_path / "gate.apk")
    assert built["signed"] is False
    built_apk = Path(built["apk"])
    assert built_apk.is_file()
    assert built["size"] > 0

    keystore = tmp_path / "test.keystore"
    subprocess.run(
        [
            str(keytool), "-genkeypair", "-keystore", str(keystore),
            "-alias", "testkey", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "365", "-storepass", "testpass", "-keypass", "testpass",
            "-dname", "CN=Test,O=Test,C=US",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )

    # apk.sign: apksigner signs and then re-reads the output to verify it; a
    # broken flag or a manifest it cannot parse would fail one of the two.
    signed = client.sign(
        built_apk,
        tmp_path / "gate-signed.apk",
        keystore=keystore,
        keystore_password="testpass",
        key_alias="testkey",
        timeout=120,
    )
    assert signed["signed"] is True
    assert signed["debug_keystore"] is False
    assert Path(signed["apk"]).is_file()
    # The signature block only makes the archive larger, never smaller.
    assert signed["size"] > built["size"]
