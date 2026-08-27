"""Android static gate: the androguard surface against a real, built APK.

The Android RE gate only classifies a *synthetic* (invalid) APK, so androguard
never actually parsed anything: ``apk.manifest`` / ``permissions`` /
``components`` / ``certificates`` / ``native_libs`` / ``classes`` / ``methods`` /
``strings`` / ``xrefs`` had no real-content coverage, and the unit tests stub
androguard out -- the same mock-shaped blind spot that hid two Ghidra bugs.
androguard 4.x reworked much of this API, so an untested surface here rots
quietly across releases.

This builds a genuine APK with apktool from a hand-written manifest (a package,
an INTERNET permission, a launcher activity) and one smali class (``Sample`` with
``greet`` returning a marker string and ``use`` calling it, so a cross-reference
exists), drops in native-lib entries, and signs it when apksigner/keytool are
present. Then it drives every androguard tool through ``AnalysisService`` and
asserts the real facts each must recover.

skip != pass: it skips only when androguard or apktool is unavailable, or apktool
cannot build the fixture. The certificate leg additionally needs apksigner and
keytool; without them the APK is left unsigned and only the unsigned envelope is
asserted.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.gate">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="AndroguardGate">
        <activity android:name="com.example.gate.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

_APKTOOL_YML = """!!brut.androlib.meta.MetaInfo
isFrameworkApk: false
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '33'
"""

# greet() holds a marker string; use() calls greet() so a cross-reference exists
# for apk.xrefs to recover. <init> is required for a loadable class.
_SAMPLE_SMALI = """.class public Lcom/example/gate/Sample;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static greet()Ljava/lang/String;
    .registers 1
    const-string v0, "ANDROGUARD_GATE_MARKER"
    return-object v0
.end method

.method public static use()Ljava/lang/String;
    .registers 1
    invoke-static {}, Lcom/example/gate/Sample;->greet()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
"""


def _build_apk(apktool: Path, work: Path) -> Path | None:
    project = work / "project"
    smali_dir = project / "smali" / "com" / "example" / "gate"
    smali_dir.mkdir(parents=True)
    (project / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (project / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "Sample.smali").write_text(_SAMPLE_SMALI, encoding="utf-8")
    for abi in ("arm64-v8a", "x86_64"):
        lib = project / "lib" / abi
        lib.mkdir(parents=True)
        (lib / "libnative.so").write_bytes(b"\x7fELFplaceholder")
    apk = work / "gate.apk"
    try:
        subprocess.run(
            [str(apktool), "b", str(project), "-o", str(apk)],
            check=False,
            capture_output=True,
            timeout=300,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    # apktool can warn (non-zero) about its bundled aapt yet still emit a usable
    # APK, so trust the artifact on disk rather than the exit code.
    return apk if apk.is_file() else None


def _sign_apk(apksigner: Path, keytool: str, apk: Path, work: Path) -> bool:
    keystore = work / "gate.keystore"
    try:
        subprocess.run(
            [
                keytool, "-genkeypair", "-keystore", str(keystore),
                "-storepass", "gatepass", "-alias", "gatekey", "-keypass", "gatepass",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "365", "-dname", "CN=Gate",
            ],
            check=True, capture_output=True, timeout=120,
        )
        subprocess.run(
            [
                str(apksigner), "sign",
                "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                "--ks", str(keystore), "--ks-pass", "pass:gatepass",
                "--key-pass", "pass:gatepass", "--ks-key-alias", "gatekey", str(apk),
            ],
            check=True, capture_output=True, timeout=120,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return True


@pytest.mark.integration
def test_android_static_surface_on_a_built_apk(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — Android static Gate not run (skip != pass)")
    settings = Settings.load()
    apktool = settings.apktool
    if apktool is None or not apktool.is_file():
        pytest.skip("apktool not configured — Android static Gate not run (skip != pass)")

    apk = _build_apk(apktool, tmp_path / "build")
    if apk is None:
        pytest.skip("apktool could not build the fixture APK — Gate not run (skip != pass)")

    apksigner = settings.apksigner
    keytool = shutil.which("keytool")
    signed = False
    if apksigner is not None and apksigner.is_file() and keytool is not None:
        signed = _sign_apk(apksigner, keytool, apk, tmp_path / "sign")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "apk"
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == "com.example.gate"
        assert str(opened.data["main_activity"]).endswith("MainActivity")
        assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.gate"
        assert "INTERNET" in manifest.data["manifest_xml"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        declared = set(permissions.data["permissions"]) | set(
            permissions.data.get("requested_permissions", [])
        )
        assert "android.permission.INTERNET" in declared

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert any(a.endswith("MainActivity") for a in components.data["activities"])
        assert str(components.data["main_activity"]).endswith("MainActivity")

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert "lib/arm64-v8a/libnative.so" in native.data["native_libs"]
        assert {"arm64-v8a", "x86_64"} <= set(native.data["abis"])

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert "Lcom/example/gate/Sample;" in classes.data["classes"]

        methods = service.apk_methods(session_id, "com.example.gate.Sample")
        assert methods.ok, methods.error
        method_names = {m["name"] for m in methods.data["methods"]}
        assert {"greet", "use"} <= method_names

        strings = service.apk_strings(session_id, limit=5000)
        assert strings.ok, strings.error
        assert "ANDROGUARD_GATE_MARKER" in strings.data["strings"]

        # use() calls greet(), so the reference walk must surface use as a caller.
        xrefs = service.apk_xrefs(session_id, "greet")
        assert xrefs.ok, xrefs.error
        assert any(c["method"] == "use" for c in xrefs.data["callers"])

        certificates = service.apk_certificates(session_id)
        assert certificates.ok, certificates.error
        if signed:
            # A real v1 signature must be read back with the CN=Gate subject.
            assert certificates.data["v1_signed"] is True
            assert certificates.data["signature_files"]
            subjects = " ".join(
                str(c.get("subject", "")) for c in certificates.data["certificates"]
            )
            assert "Gate" in subjects
        else:
            assert certificates.data["v1_signed"] is False
    finally:
        service.close_all()
