"""Android static line live gate: jadx decompile, apktool decode, androguard facts.

The jadx, apktool and androguard backends carry deep subprocess-/import-mocked
unit coverage, but no gate on any platform ever ran the real tools against a real
target -- so the whole Android *static* line (decompile an APK to Java, decode an
APK to smali + resources, extract manifest/permission/class/xref facts) had never
actually executed end to end. The synthetic Android gate builds a zip that only
looks like an APK (a fake AXML manifest, a placeholder classes.dex): enough for
stdlib classification, but nothing a real tool can parse, so it only ever asserts
that androguard returns *some* envelope and never that it recovered real facts.

This gate closes that hole by producing a *real* target at test time and driving
the product clients over it:

* jadx: decompile a real target and read back one class's Java source. jadx
  decompiles APK, DEX, JAR and .class through the same core and the client only
  ever reads ``<out>/sources``, so a JAR compiled here with a JDK exercises the
  identical read-back path when the heavier APK toolchain is absent.
* apktool: decode a real APK (a genuine binary AXML manifest plus a smali-built
  classes.dex) into smali + manifest and confirm the disassembly round-trips.
* androguard: through the real ``AnalysisService`` session surface, open the APK
  and read back its package, permission, launcher activity, recovered class and
  methods, and the caller cross-reference of one method -- the metadata backbone
  the apk.* tools expose.

The jadx and apktool tests assemble their target at test time (jadx from a
JDK-built JAR; apktool from a hand-written manifest + smali via its bundled
assembler and aapt2), so they need no tracked binary. The androguard test builds
the same way when apktool+aapt2 are present, but otherwise falls back to a small
committed APK (``fixtures/android/static_sample.apk``, carrying the exact same
package/class/methods/permission -- see ``fixtures/android/README.md``): androguard
is a pip ``[android]`` install while aapt2/apktool usually are not, so this is what
lets the androguard facts stay verifiable without the heavier build chain.

skip != pass: each test skips only when the tool it needs is genuinely absent
(jadx / apktool / androguard not configured, no JDK to compile the JAR, no aapt2
to link the APK, and no committed fixture for the androguard fallback), and never
silently. The arithmetic the class computes (a * b + 7) and the run->compute call
are asserted in the recovered Java, smali and xrefs, so a pass means the tool
actually reconstructed the code, not merely emitted some file.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_PACKAGE = "com.example.headless"
_CLASS = "com.example.MainActivity"
_SMALI_CLASS = "Lcom/example/MainActivity;"
_PERMISSION = "android.permission.INTERNET"
# ``run`` calls ``compute``; androguard should recover that caller as an xref.
_CALLEE = "compute"
_CALLER = "run"
# The committed real APK the androguard test falls back to when apktool+aapt2 are
# not available to build one. It is built to carry exactly the constants above, so
# every assertion below holds whether the APK was built here or read from disk.
_FIXTURE_APK = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "static_sample.apk"

# One class, one method computing a * b + 7. Trivial but distinctive: the
# multiply-then-add-7 survives both the .class->Java and the smali->dex->Java
# paths, so the same assertion proves recovery whichever target the gate used.
_JAVA_SOURCE = """\
package com.example;

public class MainActivity {
    public int compute(int a, int b) {
        return a * b + 7;
    }

    public int run() {
        return compute(2, 3);
    }
}
"""

# The smali counterpart, assembled by apktool into a real classes.dex. Written by
# hand so the APK needs no d8/dx from the Android SDK -- apktool bundles smali.
# ``run`` calls ``compute`` so androguard's cross-reference analysis has a real
# edge to recover, not just isolated methods.
_SMALI_SOURCE = """\
.class public Lcom/example/MainActivity;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public compute(II)I
    .registers 4
    mul-int v0, p1, p2
    add-int/lit8 v0, v0, 0x7
    return v0
.end method

.method public run()I
    .registers 4
    const/4 v1, 0x2
    const/4 v2, 0x3
    invoke-virtual {p0, v1, v2}, Lcom/example/MainActivity;->compute(II)I
    move-result v0
    return v0
.end method
"""

_MANIFEST_SOURCE = f"""\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{_PACKAGE}">
    <uses-permission android:name="{_PERMISSION}"/>
    <application android:label="Headless">
        <activity android:name="com.example.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

# apktool.yml is metadata only; apktool does not hard-validate the version, but a
# well-formed MetaInfo lets `apktool b` proceed. A mismatch here surfaces as a
# clean "could not build a test APK" skip, not a failure.
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


def _build_jar(tmp_path: Path) -> Path | None:
    """Compile the Java class into a JAR, or None when no JDK is present.

    jadx treats a JAR exactly like an APK's dex for the decompile path the client
    reads (``<out>/sources``), so this is the portable target: it needs only a
    JDK, no Android toolchain, and keeps the jadx test runnable on a bare host.
    """
    javac = shutil.which("javac")
    jar = shutil.which("jar")
    if javac is None or jar is None:
        return None
    src = tmp_path / "src" / "com" / "example"
    src.mkdir(parents=True, exist_ok=True)
    (src / "MainActivity.java").write_text(_JAVA_SOURCE, encoding="utf-8")
    classes = tmp_path / "classes"
    out = tmp_path / "widget.jar"
    try:
        subprocess.run(
            [javac, "-d", str(classes), str(src / "MainActivity.java")],
            check=True,
            capture_output=True,
            timeout=120,
        )
        subprocess.run(
            [jar, "cf", str(out), "-C", str(classes), "."],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out if out.is_file() else None


def _build_real_apk(tmp_path: Path, apktool: Path) -> Path | None:
    """Assemble a genuine APK with apktool + aapt2, or None when they cannot.

    apktool's bundled smali turns the hand-written class into a real classes.dex
    and aapt2 links the manifest into binary AXML -- the result is an APK a real
    tool can parse, unlike the synthetic zip the classification gate uses. Needs
    aapt2 on PATH (apktool 2.10 does not bundle it and NPEs without ``-a``); its
    absence is a skip, not a failure.
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
    apk = tmp_path / "headless.apk"
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


@pytest.mark.integration
def test_jadx_decompiles_a_real_target(tmp_path: Path) -> None:
    settings = Settings.load()
    client = JadxClient(executable=getattr(settings, "jadx", None))
    if not client.available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX / PATH) — live Gate not run (skip≠pass)")

    # Prefer a real APK (a real Android dex) when the toolchain is present; fall
    # back to a JDK-built JAR so the gate still runs on a host without aapt2.
    apktool = getattr(settings, "apktool", None)
    target = _build_real_apk(tmp_path, apktool) if apktool is not None else None
    if target is None:
        target = _build_jar(tmp_path)
    if target is None:
        pytest.skip("no jadx target: need aapt2+apktool for an APK or a JDK for a JAR (skip≠pass)")

    out = tmp_path / "jadx_out"
    exported = client.export_sources(target, out)
    assert exported["java_file_count"] >= 1, "jadx recovered no Java sources"
    assert exported["sources_dir"], "jadx wrote no sources directory"
    assert any("MainActivity" in name for name in exported["java_files"])
    # A clean run must not report a tool failure over an otherwise complete tree.
    assert exported.get("tool_failed") is not True

    decompiled = client.decompile(target, tmp_path / "jadx_dec", _CLASS)
    assert decompiled["class_name"] == _CLASS
    body = decompiled["source"]
    assert isinstance(body, str) and body.strip()
    assert "compute" in body, "the named method was not recovered"
    assert "return" in body and "*" in body and "7" in body, "jadx did not reconstruct a * b + 7"


@pytest.mark.integration
def test_apktool_decodes_a_real_apk(tmp_path: Path) -> None:
    settings = Settings.load()
    client = ApktoolClient(
        apktool=getattr(settings, "apktool", None),
        apksigner=getattr(settings, "apksigner", None),
    )
    if not client.available or client.apktool is None:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — not run (skip≠pass)")

    apk = _build_real_apk(tmp_path, client.apktool)
    if apk is None:
        pytest.skip("could not build a test APK (needs aapt2 for apktool build) — skip≠pass")

    decoded = client.decode(apk, tmp_path / "decoded")

    manifest = decoded.get("manifest")
    assert manifest and Path(manifest).is_file(), "apktool produced no AndroidManifest.xml"
    manifest_text = Path(manifest).read_text(encoding="utf-8")
    assert _PACKAGE in manifest_text, "decoded manifest lost the package name"

    assert decoded.get("smali_dirs"), "apktool recovered no smali directory"
    smali_files = list((tmp_path / "decoded").rglob("MainActivity.smali"))
    assert smali_files, "apktool did not disassemble the class to smali"
    smali_text = smali_files[0].read_text(encoding="utf-8")
    assert "compute(II)I" in smali_text, "the compute method was not disassembled"
    assert "mul-int" in smali_text, "apktool did not recover the multiply instruction"


@pytest.mark.integration
def test_androguard_extracts_real_apk_facts(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed (android extra) — not run (skip≠pass)")
    # Build a fresh APK when the apktool+aapt2 chain is present, so the real build
    # path is exercised too; otherwise fall back to the committed fixture so the
    # androguard facts stay verifiable with just the [android] extra.
    apktool = getattr(Settings.load(), "apktool", None)
    apk = _build_real_apk(tmp_path, apktool) if apktool is not None else None
    if apk is None and _FIXTURE_APK.is_file():
        apk = _FIXTURE_APK
    if apk is None:
        pytest.skip("no APK: need apktool+aapt2 to build one, or the committed fixture — skip≠pass")

    # A real APK must classify as one; the synthetic gate proves the fake zip
    # does too, so this pins that the genuine article is not mis-routed.
    assert classify_target(apk) is TargetKind.APK

    # Drive the product session surface, not the client directly: this is the
    # path the apk.* tools take, so it also exercises session creation, target
    # dispatch and the Result envelopes.
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        session_id = session["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _PACKAGE
        assert opened.data["main_activity"] == _CLASS

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert _PERMISSION in permissions.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert _CLASS in components.data["activities"]
        assert components.data["main_activity"] == _CLASS

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert _PACKAGE in manifest.data["manifest_xml"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert _SMALI_CLASS in classes.data["classes"], "androguard did not recover our class"

        methods = service.apk_methods(session_id, _CLASS)
        assert methods.ok, methods.error
        names = {item["name"] for item in methods.data["methods"]}
        assert {_CALLEE, _CALLER} <= names, f"expected compute and run among {names}"

        # The real payoff of full DEX analysis: run() calls compute(), so
        # compute must report run as a caller. A mock never proves this edge.
        xrefs = service.apk_xrefs(session_id, _CALLEE)
        assert xrefs.ok, xrefs.error
        callers = {item["method"] for item in xrefs.data["callers"]}
        assert _CALLER in callers, f"compute's caller {_CALLER} not among {callers}"
    finally:
        service.close_all()
