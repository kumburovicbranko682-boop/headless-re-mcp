"""APK DEX-analysis gate: apk.classes / methods / strings / xrefs on a real DEX.

The Android RE gate builds a synthetic APK whose ``classes.dex`` is a placeholder
that androguard cannot parse, so it can only assert that DEX analysis *degrades*
without crashing -- it never drives the analysis on a valid DEX. That leaves the
four DEX tools' happy path unexercised, which is exactly where an androguard API
drift would hide: a renamed or removed method (the frida-17 class of break, e.g.
``Analysis.get_classes`` / ``MethodAnalysis.get_xref_from`` /
``StringAnalysis.get_value``) fails only at runtime against a real DEX.

This gate uses a committed 660-byte real DEX (``fixtures/android/classes.dex``,
assembled from ``Hello.smali``) so the whole stack -- ``AnalyzeAPK`` through the
paginated tool envelopes -- runs against genuine bytecode. It skips when the
``android`` extra (androguard) is absent; skip is not pass.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_DEX = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "classes.dex"


def _build_apk_with_real_dex(path: Path) -> Path:
    # A placeholder manifest is fine: AnalyzeAPK still builds the DEX analysis
    # even when AXML parsing fails, and this gate only asserts the DEX tools.
    with zipfile.ZipFile(path, "w") as archive:
        archive.write(_FIXTURE_DEX, "classes.dex")
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


@pytest.mark.integration
def test_apk_dex_analysis_over_a_real_dex(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK DEX Gate not run (skip != pass)")
    if not _FIXTURE_DEX.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_DEX}")

    apk = _build_apk_with_real_dex(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # classes: the one internal class; the external Ljava/lang/Object; is
        # filtered out, so a real result is exactly [LHello;].
        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == ["LHello;"]
        assert classes.data["total"] == 1

        # methods: all three real methods resolve, via both the smali and the
        # dotted class-name form.
        methods = service.apk_methods(session_id, "Hello")
        assert methods.ok, methods.error
        names = {m["name"] for m in methods.data["methods"]}
        assert {"<init>", "decryptSecret", "main"} <= names

        # strings: the embedded constant is recovered from the DEX string pool.
        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert any(s == "s3cr3t-flag-value" for s in strings.data["strings"])

        # xrefs: main() calls decryptSecret(), so the caller must be resolved --
        # this is the get_xref_from() tuple-unpack path that would silently break
        # on an androguard API drift.
        xrefs = service.apk_xrefs(session_id, "decryptSecret")
        assert xrefs.ok, xrefs.error
        assert {"class": "LHello;", "method": "main"} in xrefs.data["callers"]
        assert xrefs.data["has_more"] is False
    finally:
        service.close_all()
