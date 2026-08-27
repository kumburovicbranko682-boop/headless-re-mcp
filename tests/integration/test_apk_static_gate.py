"""androguard static-analysis gate against a real, DEX-bearing APK.

Every other Android static test on a bare machine runs on a *synthetic* archive
whose classes.dex is a placeholder androguard cannot parse, so androguard's real
analysis -- classes, strings, methods, and especially xrefs -- had no live
coverage anywhere. This gate parses a committed real-DEX APK
(fixtures/android/sample.apk, provenance in fixtures/android/build.sh) so the
androguard path runs for real.

Its sharpest job is the xrefs regression guard: MainActivity.greet builds a
string with `+`, which compiles to a call to the *external* framework method
StringBuilder.append. xrefs used to skip every is_external() method and hand back
an authoritative-looking empty caller list for exactly these framework/crypto/
reflection APIs -- the whole point of Android xref hunting. Here a real androguard
must resolve that caller, or this goes red. skip != pass: it runs whenever
androguard is installed and only skips when it is genuinely absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "sample.apk"


def _session(service: AnalysisService) -> str:
    created = service.create_session(str(_FIXTURE))
    assert created.ok, created.error
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_androguard_resolves_real_classes_strings_and_methods() -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    service = AnalysisService()
    try:
        session_id = _session(service)

        classes = service.apk_classes(session_id, limit=100)
        assert classes.ok, classes.error
        names = classes.data["classes"]
        assert "Lcom/example/gate/MainActivity;" in names
        assert "Lcom/example/gate/Helper;" in names

        strings = service.apk_strings(session_id, limit=200)
        assert strings.ok, strings.error
        assert "H3adl3ss_marker" in strings.data["strings"]

        methods = service.apk_methods(session_id, "com.example.gate.MainActivity")
        assert methods.ok, methods.error
        method_names = {m["name"] for m in methods.data["methods"]}
        assert {"secret", "add", "greet"} <= method_names
    finally:
        service.close_all()


@pytest.mark.integration
def test_xrefs_resolve_callers_of_an_external_framework_method() -> None:
    """The regression guard: callers of StringBuilder.append must resolve."""
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    service = AnalysisService()
    try:
        session_id = _session(service)

        result = service.apk_xrefs(session_id, "append", limit=50)
        assert result.ok, result.error
        callers = result.data["callers"]
        # greet() is the only in-app caller; it must appear despite append being
        # an external (framework) method, and exactly once despite two call sites.
        assert result.data["count"] >= 1, "no callers of external append resolved"
        greet = [c for c in callers if c["method"] == "greet"]
        assert greet, f"MainActivity.greet not among callers: {callers}"
        assert greet[0]["class"] == "Lcom/example/gate/MainActivity;"
        assert len(greet) == 1, f"identical call sites not de-duplicated: {callers}"

        # A method nobody calls returns an honest empty answer, not a crash.
        nobody = service.apk_xrefs(session_id, "secret", limit=50)
        assert nobody.ok, nobody.error
        assert nobody.data["callers"] == []
        assert nobody.data["has_more"] is False
    finally:
        service.close_all()
