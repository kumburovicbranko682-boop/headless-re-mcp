"""Live APK modification gate: apktool decode/build then apksigner sign, no device.

apk.decode drives apktool's ``d``, apk.repack drives ``b``, and apk.sign drives
apksigner's sign+verify; all are JRE CLIs whose flags (apksigner's ``--ks-pass``
/ ``--key-pass`` / ``--out``, apktool's ``d -o -f`` and ``b -o``) are exactly
what a tool bump moves. None ran live before because apksigner refuses an APK
whose binary AndroidManifest.xml it cannot read a minSdkVersion from -- so these
compile a real manifest with apktool from a text skeleton, decode it back and
rebuild it, then sign the result and let apksigner verify it. Skips honestly
when apktool, apksigner, or keytool is absent (skip != pass).
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


# A smali class so the built APK carries a real classes.dex; decoding it back
# must reproduce this file under smali/, which is how the decode path proves it
# disassembled the dex rather than only copying the manifest.
_ADDER_SMALI = """.class public Lcom/example/gate/Adder;
.super Ljava/lang/Object;

.method public add(II)I
    .registers 3
    add-int v0, p1, p2
    return v0
.end method
"""


def _tool(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _write_code_skeleton(root: Path) -> None:
    """A skeleton apktool builds into an APK with both a manifest and a dex."""
    smali_dir = root / "smali" / "com" / "example" / "gate"
    smali_dir.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (root / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "Adder.smali").write_text(_ADDER_SMALI, encoding="utf-8")


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


@pytest.mark.integration
def test_apktool_decode_then_rebuild_roundtrip(tmp_path: Path) -> None:
    """apk.decode disassembles a real APK, and build reassembles the result.

    Only the build+sign direction ran live; apktool's ``d`` -- which decodes the
    binary AndroidManifest.xml back to text and the classes.dex back to smali --
    had no coverage, though its flags move on major bumps just like ``b``. Build
    an APK carrying a manifest and a dex, decode it, and assert the manifest came
    back as readable XML naming the package, the smali tree reappeared with our
    class, and no res/ was invented for an APK that has none. Then rebuild from
    that decode output, which is the actual edit workflow (decode, change, repack)
    and a stricter build input than the hand-written skeleton.
    """
    apktool = _tool("apktool")
    if apktool is None:
        pytest.skip("apktool not installed — APK decode Gate not run (skip != pass)")

    skeleton = tmp_path / "skeleton"
    skeleton.mkdir()
    _write_code_skeleton(skeleton)

    client = ApktoolClient(apktool=apktool)
    built_apk = Path(client.build(skeleton, tmp_path / "gate.apk")["apk"])
    assert built_apk.is_file()

    decoded = client.decode(built_apk, tmp_path / "decoded", timeout=120)
    manifest = Path(decoded["manifest"])
    assert manifest.is_file()
    # Binary AXML must have decoded back to text that names the package.
    manifest_text = manifest.read_text(encoding="utf-8")
    assert 'package="com.example.gate"' in manifest_text
    # The dex must have disassembled into a smali tree carrying our class.
    assert "smali" in decoded["smali_dirs"]
    smali_file = Path(decoded["decoded_dir"]) / "smali" / "com" / "example" / "gate" / "Adder.smali"
    assert smali_file.is_file()
    assert "Lcom/example/gate/Adder;" in smali_file.read_text(encoding="utf-8")
    # This APK ships no resources, so decode must not claim a res/ tree.
    assert decoded["has_resources"] is False

    # Repack the decode output: build must accept apktool's own decode tree, not
    # just a hand-authored skeleton, or the decode/edit/repack loop is broken.
    rebuilt = client.build(Path(decoded["decoded_dir"]), tmp_path / "rebuilt.apk")
    assert Path(rebuilt["apk"]).is_file()
    assert rebuilt["size"] > 0
    assert rebuilt["signed"] is False
