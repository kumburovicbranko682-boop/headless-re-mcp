"""Android DEX-analysis gate: androguard's in-process parser on a real DEX.

The apk.classes / apk.methods / apk.xrefs surface runs androguard over a real
Dalvik executable, but every unit test stubs androguard out, so nothing proved
the client maps a genuine DEX the way it claims. apktool's own decode/build has
a separate live gate; this one is the missing half -- the in-process analysis
path, not the subprocess one.

It builds the fixture the way the ELF gate compiles ``elf_fixture.c`` with gcc:
``smali`` assembles two classes into a real ``classes.dex`` (a ``Helper`` with
one method called twice by ``Main`` and one method called by nobody), ``aapt2``
links a binary-AXML manifest, and the two are zipped into an APK -- no signing,
since androguard parses the DEX and manifest regardless. Then it drives the
service session end to end and, crucially, checks that xrefs *discriminates*:
the called method reports its two call sites while the uncalled one reports
none, so a fixture that made every method look the same could not pass. Skips
(never passes) when smali, aapt2 or androguard is absent.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_PACKAGE = "com.gate.app"
# A manifest with no android:-namespaced attributes links against nothing
# beyond aapt2 itself -- no android.jar / SDK platform needed.
_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    f'package="{_PACKAGE}">\n'
    "    <application/>\n"
    "</manifest>\n"
)
# Helper.doWork() is invoked twice by Main.run(); Helper.unused() by nobody.
# That asymmetry is the whole point: xrefs must find two call sites for the
# first and none for the second.
_HELPER_SMALI = """\
.class public Lcom/gate/Helper;
.super Ljava/lang/Object;
.method public static doWork()I
    .registers 1
    const/4 v0, 0x7
    return v0
.end method
.method public static unused()I
    .registers 1
    const/4 v0, 0x0
    return v0
.end method
"""
_MAIN_SMALI = """\
.class public Lcom/gate/Main;
.super Ljava/lang/Object;
.method public static run()I
    .registers 2
    invoke-static {}, Lcom/gate/Helper;->doWork()I
    move-result v0
    invoke-static {}, Lcom/gate/Helper;->doWork()I
    move-result v1
    add-int/2addr v0, v1
    return v0
.end method
"""


def _build_real_apk(work: Path) -> Path:
    """Assemble a real DEX + binary AXML manifest into an APK, or skip."""
    smali = shutil.which("smali")
    aapt2 = shutil.which("aapt2")
    if smali is None or aapt2 is None:
        missing = "smali" if smali is None else "aapt2"
        pytest.skip(f"{missing} not installed — DEX-analysis Gate not run (skip != pass)")

    src = work / "smali" / "com" / "gate"
    src.mkdir(parents=True)
    (src / "Helper.smali").write_text(_HELPER_SMALI, encoding="utf-8")
    (src / "Main.smali").write_text(_MAIN_SMALI, encoding="utf-8")
    dex = work / "classes.dex"
    assembled = subprocess.run(
        [smali, "a", str(work / "smali"), "-o", str(dex)],
        capture_output=True,
        timeout=180,
    )
    if assembled.returncode != 0 or not dex.is_file():
        pytest.skip(f"smali could not assemble the fixture: {assembled.stderr.decode()[:200]}")

    manifest = work / "AndroidManifest.xml"
    manifest.write_text(_MANIFEST, encoding="utf-8")
    apk = work / "app.apk"
    linked = subprocess.run(
        [aapt2, "link", "-o", str(apk), "--manifest", str(manifest), "--no-auto-version"],
        capture_output=True,
        timeout=180,
    )
    if linked.returncode != 0 or not apk.is_file():
        pytest.skip(f"aapt2 could not link the fixture: {linked.stderr.decode()[:200]}")
    # aapt2 emits the binary-AXML manifest; add the assembled DEX beside it.
    with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex, "classes.dex")
    return apk


@pytest.mark.integration
def test_android_dex_analysis_maps_a_real_dex(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — DEX-analysis Gate not run (skip != pass)")
    apk = _build_real_apk(tmp_path / "fixture")

    # classify_target must recognise the built archive as an APK.
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        session_id = session["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _PACKAGE

        # classes: the two DEX-defined classes, framework classes excluded.
        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert set(classes.data["classes"]) == {"Lcom/gate/Helper;", "Lcom/gate/Main;"}

        # methods accepts dotted and smali names; both Helper methods present.
        methods = service.apk_methods(session_id, "com.gate.Helper")
        assert methods.ok, methods.error
        assert {m["name"] for m in methods.data["methods"]} == {"doWork", "unused"}

        # The discriminator: a called method reports its call sites, an
        # uncalled one reports none. A fixture where xrefs just returned
        # everything -- or nothing -- could not tell these two apart.
        called = service.apk_xrefs(session_id, "doWork")
        assert called.ok, called.error
        assert called.data["count"] == 2
        assert all(c["method"] == "run" for c in called.data["callers"])
        assert all(c["class"] == "Lcom/gate/Main;" for c in called.data["callers"])

        uncalled = service.apk_xrefs(session_id, "unused")
        assert uncalled.ok, uncalled.error
        assert uncalled.data["count"] == 0
        assert uncalled.data["has_more"] is False

        # xrefs honours its limit and says so rather than silently dropping the
        # second call site.
        capped = service.apk_xrefs(session_id, "doWork", limit=1)
        assert capped.ok, capped.error
        assert capped.data["count"] == 1
        assert capped.data["has_more"] is True
    finally:
        service.close_all()
