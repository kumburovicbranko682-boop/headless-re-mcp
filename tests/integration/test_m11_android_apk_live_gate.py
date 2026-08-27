"""M11 Android APK live gate: androguard DEX analysis + apktool decode.

The androguard ``apk.*`` surface (open/classes/methods/strings/xrefs) and apktool
decode had no live coverage: every apk unit test mocks androguard (monkeypatching
``_parsed``) or asserts structured degradation, so an androguard whose 4.x API
drifted -- the 3->4 rewrite reshaped ``get_classes`` / ``is_external`` /
``get_xref_from`` / ``get_strings`` -- or an apktool whose decode output moved
would pass the whole suite while the real tools returned nothing usable. This
runs both against a tiny committed APK, ``fixtures/android/sample.apk``: a single
``com.example.gate.Sample`` class whose ``caller`` calls ``callee``, which
returns the marker string ``APK_GATE_MARKER_STRING``. androguard must list the
class, its methods, the marker string, and resolve the caller->callee xref;
apktool must decode it back into a manifest plus a smali tree containing that
class. Each capability skips (skip != pass) when its backend is absent.

Fixture provenance: built with apktool 3.0.3 (``apktool b`` assembles the smali
into ``classes.dex`` and compiles the manifest to binary AXML via aapt2). The
readable sources are committed beside it as ``fixtures/android/sample.smali`` and
``fixtures/android/sample.AndroidManifest.xml``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.backends.apktool import ApktoolClient
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK = _PROJECT_ROOT / "fixtures" / "android" / "sample.apk"
_CLASS = "com.example.gate.Sample"


@pytest.mark.integration
def test_m11_androguard_apk_surface() -> None:
    client = ApkClient()  # construction silences androguard's loguru flood
    if not client.available:
        pytest.skip("androguard not installed — APK Gate not run (skip != pass)")
    assert _APK.is_file(), f"fixture missing: {_APK}"

    opened = client.open(_APK)
    assert opened["opened"] is True
    assert opened["package"] == "com.example.gate"

    # ApkClient silences androguard's DEBUG loguru flood on construction (~150
    # records per AnalyzeAPK, one per basic block). Prove a real analysis emits
    # no androguard records, so an unattended server's own logs are not buried.
    from loguru import logger

    origins: list[str] = []
    sink = logger.add(lambda message: origins.append(message.record["name"]), level="TRACE")
    try:
        classes = client.classes(_APK)
    finally:
        logger.remove(sink)
    assert not [name for name in origins if name.startswith("androguard")], origins

    assert any("Sample" in name for name in classes["classes"]), classes["classes"]

    methods = client.methods(_APK, _CLASS)
    names = {m["name"] for m in methods["methods"]}
    # caller/callee are the two methods the xref assertion below depends on.
    assert {"callee", "caller"} <= names, names

    strings = client.strings(_APK)
    assert any(
        "APK_GATE_MARKER_STRING" in value for value in strings["strings"]
    ), strings["strings"]

    # caller -> callee is a real invoke edge in the dex, so asking for callers of
    # callee must return caller. A wrong parse yields an empty caller list.
    xrefs = client.xrefs(_APK, "callee")
    assert xrefs["count"] >= 1
    assert any(
        caller["method"] == "caller" and "Sample" in caller["class"]
        for caller in xrefs["callers"]
    ), xrefs["callers"]


@pytest.mark.integration
def test_m11_apktool_decode(tmp_path: Path) -> None:
    client = ApktoolClient(getattr(Settings.load(), "apktool", None))
    if not client.available:
        pytest.skip("apktool not installed/configured — apktool Gate not run (skip != pass)")
    assert _APK.is_file(), f"fixture missing: {_APK}"

    decoded = client.decode(_APK, tmp_path / "decoded")
    assert decoded["manifest"] is not None
    assert decoded["smali_dirs"], decoded
    # The decoded smali tree must carry our class back out, proving baksmali ran
    # rather than only the manifest landing on disk.
    assert list((tmp_path / "decoded").rglob("Sample.smali")), "decoded tree has no Sample.smali"
