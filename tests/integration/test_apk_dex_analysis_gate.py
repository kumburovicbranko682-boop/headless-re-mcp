"""APK DEX-analysis gate: apk.classes / methods / strings / xrefs on a real DEX.

The Android RE gate builds a synthetic APK whose ``classes.dex`` is a placeholder
that androguard cannot parse, so it can only assert that DEX analysis *degrades*
without crashing -- it never drives the analysis on a valid DEX. That leaves the
four DEX tools' happy path unexercised, which is exactly where an androguard API
drift would hide: a renamed or removed method (the frida-17 class of break, e.g.
``Analysis.get_classes`` / ``MethodAnalysis.get_xref_from`` /
``StringAnalysis.get_value``) fails only at runtime against a real DEX.

This gate uses the committed real APK (``fixtures/android/fixture.apk``, built
from ``fixtures/android/src`` with apktool) so the whole stack -- ``AnalyzeAPK``
through the paginated tool envelopes -- runs against genuine bytecode. It skips
when the ``android`` extra (androguard) is absent; skip is not pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_APK = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "fixture.apk"
_CLASS_SMALI = "Lcom/example/fixture/MainActivity;"
_CLASS_DOTTED = "com.example.fixture.MainActivity"


@pytest.mark.integration
def test_apk_dex_analysis_over_a_real_dex(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK DEX Gate not run (skip != pass)")
    if not _FIXTURE_APK.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_APK}")

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE_APK))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # classes: the one internal class; external types like Ljava/lang/Object;
        # are filtered out, so a real result is exactly the packaged class.
        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == [_CLASS_SMALI]
        assert classes.data["total"] == 1

        # methods: all three real methods resolve via the dotted class-name form.
        methods = service.apk_methods(session_id, _CLASS_DOTTED)
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
        assert {"class": _CLASS_SMALI, "method": "main"} in xrefs.data["callers"]
        assert xrefs.data["has_more"] is False
    finally:
        service.close_all()
