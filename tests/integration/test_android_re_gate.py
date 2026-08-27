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

# A manifest declaring permissions and components so the permissions/components
# accessors have real values to read back, not just the metadata the plain
# manifest carries. apktool compiles these into the binary AXML.
_RICH_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.gate">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application android:label="Gate">
        <activity android:name="com.example.gate.MainActivity"/>
        <service android:name="com.example.gate.SyncService"/>
    </application>
</manifest>
"""

# A smali class apktool assembles into a real classes.dex on build. It carries
# exactly the facts the DEX surface must read back: a class name, three named
# methods, a unique string constant, and an internal call site (run -> add) so
# xrefs has a non-external caller to find. apktool's bundled smali assembler is
# what produces the dex, so no Android SDK / d8 is needed.
_ADDER_SMALI = """.class public Lcom/example/gate/Adder;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public add(II)I
    .registers 3
    add-int v0, p1, p2
    return v0
.end method

.method public greet()Ljava/lang/String;
    .registers 2
    const-string v0, "gate-secret-string"
    return-object v0
.end method

.method public run()I
    .registers 4
    const/4 v1, 0x1
    const/4 v2, 0x2
    invoke-virtual {p0, v1, v2}, Lcom/example/gate/Adder;->add(II)I
    move-result v0
    return v0
.end method
"""


def _build_real_apk(tmp_path: Path, *, with_code: bool = False) -> Path:
    """Compile a real APK from a text manifest, or skip if apktool cannot.

    With ``with_code`` a smali class is dropped in so apktool assembles a real
    classes.dex, which the androguard DEX surface (classes/methods/strings/xrefs)
    needs; without it the APK is manifest-only, enough for the metadata paths.
    """
    apktool = shutil.which("apktool")
    if apktool is None:
        pytest.skip("apktool not installed — cannot compile a real manifest (skip != pass)")
    skeleton = tmp_path / "src"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_REAL_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_REAL_APKTOOL_YML, encoding="utf-8")
    if with_code:
        smali_dir = skeleton / "smali" / "com" / "example" / "gate"
        smali_dir.mkdir(parents=True)
        (smali_dir / "Adder.smali").write_text(_ADDER_SMALI, encoding="utf-8")
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


def _build_apk_with_manifest_extras(tmp_path: Path) -> Path:
    """Compile an APK declaring permissions, components, and native libs.

    apktool preserves a ``lib/<abi>/*.so`` tree into the archive and compiles the
    permission/component declarations into the binary manifest, so androguard has
    real values to recover. Skips (not fails) when apktool is missing or cannot
    build here, like the other real-APK helper.
    """
    apktool = shutil.which("apktool")
    if apktool is None:
        pytest.skip("apktool not installed — cannot compile a real manifest (skip != pass)")
    skeleton = tmp_path / "rich"
    (skeleton / "lib" / "arm64-v8a").mkdir(parents=True)
    (skeleton / "lib" / "x86_64").mkdir(parents=True)
    (skeleton / "AndroidManifest.xml").write_text(_RICH_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_REAL_APKTOOL_YML, encoding="utf-8")
    # Content is irrelevant to the enumeration; the paths are what matter.
    (skeleton / "lib" / "arm64-v8a" / "libgate.so").write_bytes(b"\x7fELF-arm64-stub")
    (skeleton / "lib" / "x86_64" / "libgate.so").write_bytes(b"\x7fELF-x86-stub")
    out = tmp_path / "rich.apk"
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


@pytest.mark.integration
def test_androguard_reads_permissions_components_and_native_libs(tmp_path: Path) -> None:
    """The permission/component/native-lib accessors must read real values.

    The manifest test proves package and SDK levels decode; these three
    accessors read different parts of the same APK -- the permission list and
    component tags from the binary AXML, and the abi set from the zip's lib/
    entries -- and only ever ran against the synthetic archive's backend_error
    path. Declare two permissions, an activity, a service, and two native libs,
    then assert each accessor returns exactly what was compiled in, so an
    androguard change to any of these surfaces fails instead of silently
    under-reporting an app's capabilities.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — success path not exercised (skip != pass)")
    apk = _build_apk_with_manifest_extras(tmp_path)

    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert "android.permission.INTERNET" in perms.data["permissions"]
        assert "android.permission.CAMERA" in perms.data["permissions"]

        comps = service.apk_components(session_id)
        assert comps.ok, comps.error
        assert "com.example.gate.MainActivity" in comps.data["activities"]
        assert "com.example.gate.SyncService" in comps.data["services"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
        assert "lib/arm64-v8a/libgate.so" in libs.data["native_libs"]
        assert libs.data["count"] == 2
    finally:
        service.close_all()


def _v1_sign(apk: Path, tmp_path: Path) -> Path:
    """Mint a key and produce a v1 (JAR) signed copy, or skip if tools are absent.

    androguard's certificate reader parses the v1 signature block (META-INF
    CERT/RSA), so the APK must be v1-signed for the success path to exist; the v2+
    schemes it defaults to leave that block empty.
    """
    apksigner = shutil.which("apksigner")
    keytool = shutil.which("keytool")
    if apksigner is None or keytool is None:
        pytest.skip("apksigner/keytool not installed — cannot v1-sign (skip != pass)")
    keystore = tmp_path / "sign.jks"
    subprocess.run(
        [
            keytool, "-genkeypair", "-keystore", str(keystore), "-alias", "k",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "365",
            "-storepass", "testpass", "-keypass", "testpass",
            "-dname", "CN=GateTest,O=GateOrg,C=US",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    signed = tmp_path / "signed.apk"
    proc = subprocess.run(
        [
            apksigner, "sign", "--ks", str(keystore), "--ks-pass", "pass:testpass",
            "--ks-key-alias", "k", "--key-pass", "pass:testpass",
            "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
            "--out", str(signed), str(apk),
        ],
        capture_output=True,
        timeout=120,
    )
    if proc.returncode != 0 or not signed.is_file():
        pytest.skip(
            f"apksigner v1 sign failed here — Gate not run (skip != pass): "
            f"{proc.stderr.decode('utf-8', 'replace')[:200]}"
        )
    return signed


@pytest.mark.integration
def test_androguard_reads_a_v1_signature(tmp_path: Path) -> None:
    """apk.certificates must parse a real v1 signature, not just the empty case.

    The synthetic archive's fake CERT.RSA only reaches the degraded path, so the
    certificate reader (androguard hands back asn1crypto objects, whose surface
    it wraps defensively) never ran on a genuine signature. Sign a real APK with
    the v1 scheme and assert the accessor reports it signed, finds the .RSA block,
    returns one certificate, and computes a SHA-256 fingerprint -- so a break in
    that parse fails here instead of silently reporting an app as unsigned.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — success path not exercised (skip != pass)")
    apk = _build_apk_with_manifest_extras(tmp_path)
    signed = _v1_sign(apk, tmp_path)

    service = AnalysisService()
    try:
        created = service.create_session(str(signed), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is True
        assert any(str(name).upper().endswith(".RSA") for name in certs.data["signature_files"])
        certificates = certs.data["certificates"]
        assert len(certificates) == 1
        # A real fingerprint over the DER cert: non-empty and hex once the
        # colon/space grouping androguard emits is stripped.
        fingerprint = str(certificates[0]["sha256"])
        hex_only = fingerprint.replace(":", "").replace(" ", "")
        assert hex_only, "no sha256 fingerprint computed for the certificate"
        assert all(ch in "0123456789abcdefABCDEF" for ch in hex_only)
    finally:
        service.close_all()


@pytest.mark.integration
def test_androguard_dex_analysis_reads_classes_methods_strings_xrefs(tmp_path: Path) -> None:
    """Drive the whole DEX surface against a real classes.dex, not a placeholder.

    classes/methods/strings/xrefs are the heart of APK static analysis, yet every
    other test runs on the synthetic archive whose classes.dex is 'dex\\n035...'
    garbage that only reaches the backend_error path -- so a renamed androguard
    accessor (its 4.x rewrite already moved this surface once) would pass every
    test and only fail on a user's real app. apktool assembles a smali class into
    a genuine dex here, and we assert the four operations return the exact class,
    methods, embedded string, and internal caller we compiled in. The static
    contract guard in the unit suite checks the API still exists; this checks it
    still reads correctly.
    """
    from headless_re_mcp.backends.apk.client import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — DEX surface not exercised (skip != pass)")
    apk = _build_real_apk(tmp_path, with_code=True)

    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # classes: the one compiled class, no framework noise (externals filtered).
        classes = service.apk_classes(session_id, limit=50)
        assert classes.ok, classes.error
        assert "Lcom/example/gate/Adder;" in classes.data["classes"]

        # methods: resolvable by both the smali and dotted class name forms.
        methods = service.apk_methods(session_id, "Lcom/example/gate/Adder;", limit=50)
        assert methods.ok, methods.error
        names = {m["name"] for m in methods.data["methods"]}
        assert {"<init>", "add", "greet", "run"} <= names
        dotted = service.apk_methods(session_id, "com.example.gate.Adder", limit=50)
        assert dotted.ok, dotted.error
        assert dotted.data["count"] == methods.data["count"]

        # strings: the unique constant we compiled in must survive DEX parsing.
        strings = service.apk_strings(session_id, limit=500)
        assert strings.ok, strings.error
        assert "gate-secret-string" in strings.data["strings"]

        # xrefs: run() invokes add(), so add's callers include the internal run().
        xrefs = service.apk_xrefs(session_id, "add", limit=50)
        assert xrefs.ok, xrefs.error
        callers = {(c["class"], c["method"]) for c in xrefs.data["callers"]}
        assert ("Lcom/example/gate/Adder;", "run") in callers
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
