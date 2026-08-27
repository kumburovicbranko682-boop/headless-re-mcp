"""Live jadx gate: decompile a real classes.dex back to Java source.

apk.decompile / apk.export_sources shell out to jadx with ``--output-dir`` and
read the result from a ``sources/<pkg>/<Class>.java`` tree -- both the flags and
that layout are exactly what a jadx major bump moves, and neither ran live
before because there was no APK with real code to decompile. apktool assembles a
smali class into a genuine dex here, then JadxClient decompiles it and we assert
the recovered Java carries the methods and string constant we compiled in.

jadx is a ~100 MB JRE app, not something apt/pip installs, so it is discovered
via ``HEADLESS_RE_JADX`` or ``jadx`` on PATH and the gate skips honestly when it
is absent (skip != pass), the same stance the Ghidra adapter takes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.gate">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <application android:label="Gate"></application>
</manifest>
"""

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


def _find_jadx() -> Path | None:
    override = os.environ.get("HEADLESS_RE_JADX")
    if override and Path(override).is_file():
        return Path(override)
    found = shutil.which("jadx") or shutil.which("jadx.bat")
    return Path(found) if found else None


def _build_apk_with_code(tmp_path: Path) -> Path:
    apktool = shutil.which("apktool")
    if apktool is None:
        pytest.skip("apktool not installed — cannot assemble a dex (skip != pass)")
    skeleton = tmp_path / "src"
    smali_dir = skeleton / "smali" / "com" / "example" / "gate"
    smali_dir.mkdir(parents=True)
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "Adder.smali").write_text(_ADDER_SMALI, encoding="utf-8")
    out = tmp_path / "gate.apk"
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
def test_jadx_decompiles_a_compiled_class_back_to_java(tmp_path: Path) -> None:
    jadx = _find_jadx()
    if jadx is None:
        pytest.skip("jadx not installed (set HEADLESS_RE_JADX) — Gate not run (skip != pass)")
    apk = _build_apk_with_code(tmp_path)
    client = JadxClient(jadx)
    assert client.available

    out = tmp_path / "jadx-out"
    result = client.decompile(apk, out, "com.example.gate.Adder", timeout=180)
    assert result["class_name"] == "com.example.gate.Adder"
    assert Path(result["path"]).is_file()
    source = result["source"]
    # jadx recovers method bodies, not just signatures: add returns a sum, greet
    # returns the exact constant we compiled, and run calls add -- so a decompile
    # that silently produced stubs (or the wrong class) fails here.
    assert "class Adder" in source
    assert "public int add(" in source
    assert "gate-secret-string" in source
    assert "return add(" in source

    # A class jadx never emitted must be a structured not_found, not a stray file.
    with pytest.raises(JadxError) as caught:
        client.decompile(apk, out, "com.example.gate.DoesNotExist", timeout=180)
    assert caught.value.code == "not_found"


@pytest.mark.integration
def test_jadx_export_sources_lists_the_decompiled_tree(tmp_path: Path) -> None:
    jadx = _find_jadx()
    if jadx is None:
        pytest.skip("jadx not installed (set HEADLESS_RE_JADX) — Gate not run (skip != pass)")
    apk = _build_apk_with_code(tmp_path)
    client = JadxClient(jadx)

    out = tmp_path / "jadx-sources"
    result = client.export_sources(apk, out, timeout=180)
    assert result["java_file_count"] >= 1
    # The listing is relative to the output root and must include our class so a
    # caller can find what to read; a layout change in jadx would drop it.
    assert any(name.endswith("com/example/gate/Adder.java") for name in result["java_files"])
    assert result["sources_dir"] is not None
    assert Path(result["sources_dir"]).is_dir()
