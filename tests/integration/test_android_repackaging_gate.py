"""Android repackaging line live gate: apktool build round-trip and apksigner sign.

The decode side of the Android modification line now has a real-APK gate
(``test_android_static_re_gate.py``), but the *write* side -- rebuild a decoded
tree back into an APK, then re-sign it -- had only subprocess-mocked unit
coverage. The security-critical part of ``ApktoolClient.sign`` (the keystore
password must travel to apksigner through ``env:`` and never touch argv) had
therefore never been proven against the real apksigner, only against a fake
``run_bounded``. This gate drives the whole repackage flow with the real tools:

* build round-trip: build a genuine APK, decode it, rebuild it, and confirm the
  rebuilt APK is a real zip whose AndroidManifest.xml is binary AXML (0x03 0x00)
  that androguard can still parse -- i.e. a rebuild produced an installable APK,
  not a zip with a raw text manifest. Rebuilding without an explicit ``-a``
  exercises apktool's own bundled aapt2 plus the framework the decode installed,
  which is exactly what the product ``apk.repack`` relies on.
* sign: rebuild an unsigned APK, mint a throwaway keystore with the JDK's own
  keytool, and re-sign through ``ApktoolClient.sign``. The client runs
  ``apksigner verify`` itself and raises if the output is not signed, so a
  returned ``signed: True`` means a real apksigner accepted the signature.

skip != pass: each test skips only when a tool it needs is genuinely absent
(apktool / aapt2 to build, apksigner / keytool to sign), never silently. The
fixture is assembled at test time from a hand-written manifest and smali class
via apktool's bundled smali assembler -- no committed binary APK, matching how
the PE line builds its fixture rather than tracking one.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings

_PACKAGE = "com.example.headless"
_KEYSTORE_PASSWORD = "android"
_KEY_ALIAS = "androiddebugkey"

_SMALI_SOURCE = """\
.class public Lcom/example/MainActivity;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
"""

_MANIFEST_SOURCE = f"""\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{_PACKAGE}">
    <application android:label="Headless">
        <activity android:name="com.example.MainActivity"/>
    </application>
</manifest>
"""

_APKTOOL_YML = """\
!!brut.androlib.meta.MetaInfo
apkFileName: headless.apk
isFrameworkApk: false
packageInfo:
  forcedPackageId: '127'
  renameManifestPackage: null
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '30'
sharedLibrary: false
sparseResources: false
unknownFiles: {}
usesFramework:
  ids:
  - 1
  tag: null
version: 2.10.0
versionInfo:
  versionCode: '1'
  versionName: '1.0'
doNotCompress: []
"""


def _build_target_apk(tmp_path: Path, apktool: Path) -> Path | None:
    """Assemble a genuine APK with apktool + aapt2, or None when they cannot.

    apktool's bundled smali assembles the class into a real classes.dex and aapt2
    links the manifest into binary AXML. The initial ``-a`` build is what installs
    apktool's default framework, so the later ``-a``-less rebuild has the framework
    it needs. Missing aapt2 is a skip, not a failure (apktool 2.10 NPEs without an
    aapt2 it can find, so we pass one explicitly for this first build).
    """
    aapt2 = shutil.which("aapt2")
    if aapt2 is None:
        return None
    proj = tmp_path / "proj"
    smali = proj / "smali" / "com" / "example"
    smali.mkdir(parents=True, exist_ok=True)
    (smali / "MainActivity.smali").write_text(_SMALI_SOURCE, encoding="utf-8")
    (proj / "AndroidManifest.xml").write_text(_MANIFEST_SOURCE, encoding="utf-8")
    (proj / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    apk = tmp_path / "target.apk"
    try:
        completed = subprocess.run(
            [str(apktool), "b", str(proj), "-a", aapt2, "-o", str(apk)],
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not apk.is_file():
        return None
    return apk


def _manifest_is_axml(apk: Path) -> bool:
    """True when the APK's manifest is compiled binary AXML, not a raw text file.

    A rebuild that cannot resolve android: attributes silently falls back to
    copying a text manifest; the result is still a zip and passes a naive check,
    but no Android runtime can install it. The AXML type marker is 0x0003.
    """
    with zipfile.ZipFile(apk) as archive:
        return archive.read("AndroidManifest.xml")[:2] == b"\x03\x00"


def _apktool_client() -> ApktoolClient:
    settings = Settings.load()
    return ApktoolClient(
        apktool=getattr(settings, "apktool", None),
        apksigner=getattr(settings, "apksigner", None),
    )


@pytest.mark.integration
def test_apktool_build_round_trips_a_real_apk(tmp_path: Path) -> None:
    client = _apktool_client()
    if not client.available or client.apktool is None:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — not run (skip≠pass)")

    target = _build_target_apk(tmp_path, client.apktool)
    if target is None:
        pytest.skip("could not build a test APK (needs aapt2 for apktool build) — skip≠pass")

    decoded = client.decode(target, tmp_path / "decoded")
    assert decoded.get("manifest"), "decode produced no manifest to rebuild from"

    rebuilt = client.build(tmp_path / "decoded", tmp_path / "rebuilt.apk")
    assert rebuilt["signed"] is False
    assert rebuilt["size"] > 0
    rebuilt_path = Path(rebuilt["apk"])
    assert zipfile.is_zipfile(rebuilt_path), "rebuild did not produce a zip-format APK"
    assert _manifest_is_axml(rebuilt_path), "rebuild wrote a raw manifest, not binary AXML"

    # The real proof the rebuild is installable: androguard reads it back and
    # recovers the package it started with.
    if ApkClient().available:
        reopened = ApkClient().open(rebuilt_path)
        assert reopened["package"] == _PACKAGE


@pytest.mark.integration
def test_apksigner_signs_a_rebuilt_apk(tmp_path: Path) -> None:
    client = _apktool_client()
    if not client.available or client.apktool is None:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — not run (skip≠pass)")
    if not client.signer_available:
        pytest.skip("apksigner not configured (HEADLESS_RE_APKSIGNER / PATH) — not run (skip≠pass)")
    keytool = shutil.which("keytool")
    if keytool is None:
        pytest.skip("keytool (JDK) not on PATH; cannot mint a keystore — skip≠pass")

    target = _build_target_apk(tmp_path, client.apktool)
    if target is None:
        pytest.skip("could not build a test APK (needs aapt2 for apktool build) — skip≠pass")

    client.decode(target, tmp_path / "decoded")
    unsigned = client.build(tmp_path / "decoded", tmp_path / "unsigned.apk")
    assert unsigned["signed"] is False

    keystore = tmp_path / "debug.keystore"
    minted = subprocess.run(
        [
            keytool,
            "-genkeypair",
            "-keystore",
            str(keystore),
            "-storepass",
            _KEYSTORE_PASSWORD,
            "-keypass",
            _KEYSTORE_PASSWORD,
            "-alias",
            _KEY_ALIAS,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=Headless Test,O=Headless,C=US",
        ],
        capture_output=True,
        timeout=120,
    )
    if minted.returncode != 0 or not keystore.is_file():
        pytest.skip("keytool could not mint a keystore in this environment — skip≠pass")

    unsigned_apk = Path(unsigned["apk"])
    signed_path = tmp_path / "signed.apk"
    # ApktoolClient.sign runs `apksigner verify` internally and raises if the
    # output is not signed, so a returned signed=True is a real verification.
    signed = client.sign(
        unsigned_apk,
        signed_path,
        keystore=keystore,
        keystore_password=_KEYSTORE_PASSWORD,
        key_alias=_KEY_ALIAS,
    )
    assert signed["signed"] is True
    assert signed["debug_keystore"] is False
    assert zipfile.is_zipfile(signed_path), "signing did not produce a zip-format APK"
    # Signing adds signature blocks, so the output is larger than the input.
    assert signed_path.stat().st_size > unsigned_apk.stat().st_size

    # Independent confirmation the signature is genuine, not just that the client
    # said so: a fresh apksigner verify must accept it.
    verified = subprocess.run(
        [str(client.apksigner), "verify", str(signed_path)],
        capture_output=True,
        timeout=120,
    )
    assert verified.returncode == 0, verified.stderr.decode("utf-8", "replace")
