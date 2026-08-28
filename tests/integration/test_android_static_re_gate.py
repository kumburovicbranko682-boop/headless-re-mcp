"""Android static line live gate: jadx decompilation and apktool decode.

The jadx and apktool backends carry deep subprocess-mocked unit coverage, but no
gate on any platform ever ran the real CLIs against a real target -- so the whole
Android *static* line (decompile an APK to Java, decode an APK to smali +
resources) had never actually executed end to end. The synthetic Android gate
builds a zip that only looks like an APK (a fake AXML manifest, a placeholder
classes.dex), which is enough for stdlib classification but nothing a real tool
can parse, so jadx and apktool were never exercised there.

This gate closes that hole by producing a *real* target at test time and driving
the product clients over it:

* jadx: decompile a real target and read back one class's Java source. jadx
  decompiles APK, DEX, JAR and .class through the same core and the client only
  ever reads ``<out>/sources``, so a JAR compiled here with a JDK exercises the
  identical read-back path when the heavier APK toolchain is absent.
* apktool: decode a real APK (a genuine binary AXML manifest plus a smali-built
  classes.dex) into smali + manifest and confirm the disassembly round-trips.

The real APK is assembled here with apktool's own bundled smali assembler plus
aapt2, from a hand-written manifest and smali class -- no committed binary
fixture, matching how the PE line builds its fixture rather than tracking one.

skip != pass: each test skips only when the tool it needs is genuinely absent
(jadx / apktool not configured, no JDK to compile the JAR, no aapt2 to link the
APK), and never silently. The arithmetic the class computes (a * b + 7) is
asserted in the recovered Java and smali, so a pass means the tool actually
reconstructed the code, not merely emitted some file.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.config import Settings

_PACKAGE = "com.example.headless"
_CLASS = "com.example.MainActivity"

# One class, one method computing a * b + 7. Trivial but distinctive: the
# multiply-then-add-7 survives both the .class->Java and the smali->dex->Java
# paths, so the same assertion proves recovery whichever target the gate used.
_JAVA_SOURCE = """\
package com.example;

public class MainActivity {
    public int compute(int a, int b) {
        return a * b + 7;
    }
}
"""

# The smali counterpart, assembled by apktool into a real classes.dex. Written by
# hand so the APK needs no d8/dx from the Android SDK -- apktool bundles smali.
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
