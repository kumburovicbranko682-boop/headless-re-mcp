"""Live jadx gate: decompile a real APK (dex), not just a jar.

The android tools gate runs jadx on a jar, which needs only a JDK. But jadx's
job in this project is APKs, and an APK reaches the decompiler through a
different front end -- the dex loader -- than a jar does. This gate assembles a
real APK with apktool (its smali assembler produces a genuine classes.dex) and
decompiles it, asserting jadx recovered the class from dex and that the emitted
Java reflects the bytecode: mangle's ``(x ^ 0x41) + 7`` arithmetic, reveal's
call into mangle, and the string constant. It also checks the whole-APK export
tree and the not_found contract. skip != pass when jadx or apktool is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.config import Settings

_PACKAGE = "com.headlessre.gate"
_MARKER = "H3adl3ss-RE-androguard-7c1"
_CLASS_DOTTED = _PACKAGE + ".Secret"
_CLASS_SMALI = "Lcom/headlessre/gate/Secret;"

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"

# reveal() calls mangle() and holds the marker string; mangle() is (x^0x41)+7.
_SMALI = """.class public Lcom/headlessre/gate/Secret;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static mangle(I)I
    .registers 2
    xor-int/lit8 v0, p0, 0x41
    add-int/lit8 v0, v0, 0x7
    return v0
.end method

.method public static reveal()Ljava/lang/String;
    .registers 2
    const/4 v1, 0x5
    invoke-static {v1}, Lcom/headlessre/gate/Secret;->mangle(I)I
    move-result v1
    const-string v0, "H3adl3ss-RE-androguard-7c1"
    return-object v0
.end method
"""


def _build_apk(client: ApktoolClient, tmp_path: Path) -> Path:
    skeleton = tmp_path / "skeleton"
    smali_dir = skeleton / "smali" / "com" / "headlessre" / "gate"
    smali_dir.mkdir(parents=True)
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")
    (smali_dir / "Secret.smali").write_text(_SMALI, encoding="utf-8")
    out = tmp_path / "out.apk"
    built = client.build(skeleton, out)
    assert Path(built["apk"]).is_file()
    assert built["size"] > 0
    return out


@pytest.mark.integration
def test_android_jadx_decompiles_a_real_apk(tmp_path: Path) -> None:
    settings = Settings.load()
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    jadx = JadxClient(executable=settings.jadx)
    if not jadx.available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX / PATH) — skip != pass")

    apk = _build_apk(apktool, tmp_path)

    # Whole-APK export: the assembled class lands in the sources tree.
    exported = jadx.export_sources(apk, tmp_path / "jout")
    assert exported["sources_dir"] is not None
    assert exported["java_file_count"] >= 1, exported
    assert any(name.endswith("gate/Secret.java") for name in exported["java_files"]), exported

    # Decompile the class by dotted name: jadx recovered it from dex, and the
    # emitted Java reflects the bytecode, not just an empty stub.
    decompiled = jadx.decompile(apk, tmp_path / "jout2", _CLASS_DOTTED)
    assert decompiled["class_name"] == _CLASS_DOTTED
    source = str(decompiled["source"])
    assert f"package {_PACKAGE};" in source, source
    assert "class Secret" in source, source
    # dex front end, not the jar path -- jadx annotates the origin.
    assert "classes.dex" in source, source
    # mangle's arithmetic survives: (x ^ 0x41) + 7, jadx renders 0x41 as 65.
    assert "mangle(int" in source, source
    assert "^ 65" in source and "+ 7" in source, source
    # reveal's call edge into mangle and its string constant are both recovered.
    assert "mangle(5)" in source, source
    assert _MARKER in source, source

    # The smali/JVM form of the name resolves to the same file.
    by_smali = jadx.decompile(apk, tmp_path / "jout3", _CLASS_SMALI)
    assert by_smali["path"].endswith("Secret.java")
    assert _MARKER in str(by_smali["source"])

    # Contract: a class that was never decompiled fails closed with not_found.
    with pytest.raises(JadxError) as missing:
        jadx.decompile(apk, tmp_path / "jout4", _PACKAGE + ".DoesNotExist")
    assert missing.value.code == "not_found"
