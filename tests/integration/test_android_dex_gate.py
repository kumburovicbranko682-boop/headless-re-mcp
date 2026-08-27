"""Live androguard gate: real DEX analysis over a real APK.

The android RE gate builds a *synthetic* (deliberately invalid) APK to check
session classification and safe degradation, so androguard's actual analysis --
manifest reading and, more importantly, the DEX-level class/method/string/xref
surface reached through AnalyzeAPK -- is never exercised anywhere. This gate
assembles a real APK with apktool (its smali assembler turns a hand-written
class into a genuine classes.dex; a framework-free manifest keeps aapt2 from
needing an Android SDK) and then drives ApkClient against it, asserting:

- the manifest package is recovered (the light, manifest-only path),
- the DEX class is discovered and its methods enumerated with descriptors,
- a marker string constant is recovered from the string pool,
- the intra-DEX call graph is resolved (reveal -> mangle) via xrefs.

Skips honestly when apktool (needs a JRE) or androguard is missing. skip != pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool.client import ApktoolClient
from headless_re_mcp.config import Settings

_PACKAGE = "com.headlessre.gate"
_MARKER = "H3adl3ss-RE-androguard-7c1"
_CLASS_SMALI = "Lcom/headlessre/gate/Secret;"

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n</manifest>\n'
)
# The MetaInfo header is what apktool reads back; a framework-free manifest keeps
# aapt2 from needing an installed android.jar to resolve android:* attributes.
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"

# reveal() calls mangle() and holds the marker string, giving androguard a real
# class, two methods, a string constant and one intra-DEX call edge to resolve.
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
def test_android_dex_classes_methods_strings_and_xrefs(tmp_path: Path) -> None:
    settings = Settings.load()
    apktool = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not apktool.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")
    apk_client = ApkClient()
    if not apk_client.available:
        pytest.skip("androguard not installed — DEX Gate not run (skip != pass)")

    apk = _build_apk(apktool, tmp_path)

    # Light path: the manifest package is read without DEX analysis.
    opened = apk_client.open(apk)
    assert opened["opened"] is True
    assert opened["package"] == _PACKAGE
    assert apk_client.manifest(apk)["package"] == _PACKAGE

    # Full DEX path: the assembled class is discovered.
    classes = apk_client.classes(apk)
    assert _CLASS_SMALI in classes["classes"], classes

    # Methods resolve by dotted name (exercises _dotted_to_smali) with descriptors.
    methods = apk_client.methods(apk, _PACKAGE + ".Secret")
    assert methods["class_name"] == _CLASS_SMALI
    by_name = {m["name"]: m for m in methods["methods"]}
    assert {"mangle", "reveal", "<init>"} <= set(by_name), by_name
    assert by_name["mangle"]["descriptor"] == "(I)I", by_name["mangle"]
    assert "static" in by_name["reveal"]["access"], by_name["reveal"]

    # The string constant is recovered from the DEX string pool.
    strings = apk_client.strings(apk)
    assert _MARKER in strings["strings"], strings["strings"][:20]

    # The intra-DEX call graph is resolved: reveal() calls mangle().
    xrefs = apk_client.xrefs(apk, "mangle")
    callers = {(c["class"], c["method"]) for c in xrefs["callers"]}
    assert (_CLASS_SMALI, "reveal") in callers, xrefs
