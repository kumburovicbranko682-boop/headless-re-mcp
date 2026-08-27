"""Android static gate: androguard's real parse path on a committed APK.

The sibling ``test_android_re_gate`` builds a synthetic archive whose manifest
is not valid AXML, so it can only prove the backend *degrades* cleanly. Nothing
exercised androguard's happy path -- the package, versions, permissions,
components, certificate, and native ABIs a real capture depends on, nor the
full DEX analysis behind classes/methods/strings/xrefs -- so a regression in
that extraction would pass CI unseen. This gate consumes a committed, v1-signed
minimal APK carrying a real one-class DEX (see
fixtures/android/build_minimal_apk.py) and asserts the extracted facts. skip !=
pass: it skips only when androguard is not installed, and says so.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "minimal.apk"


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


@pytest.mark.integration
def test_android_apk_static_happy_path() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    assert classify_target(_FIXTURE) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        assert created.ok, created.error
        session = created.data["session"]
        session_id = session["id"]
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True
        # Stdlib DEX header facts: the fixture's one-class, one-method DEX.
        assert meta["dex"]["versions"] == ["035"]
        assert meta["dex"]["class_count"] == 1
        assert meta["dex"]["method_count"] == 1

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        info = opened.data
        assert info["package"] == "com.example.headless"
        assert info["version_name"] == "1.0"
        assert info["version_code"] == "1"
        assert info["min_sdk"] == "21"
        assert info["target_sdk"] == "33"
        assert info["main_activity"] == "com.example.headless.MainActivity"
        assert info["permission_count"] == 1
        assert set(info["native_abis"]) == {"arm64-v8a", "x86_64"}

        # The stdlib AXML facts attached at session creation must agree with
        # androguard's parse -- the same package, versions, SDK levels and
        # permission read two independent ways (androguard reports the numeric
        # ones as strings, so compare with a cast).
        tool_free = meta["manifest"]
        assert tool_free["package"] == info["package"]
        assert str(tool_free["version_code"]) == info["version_code"]
        assert tool_free["version_name"] == info["version_name"]
        assert str(tool_free["min_sdk"]) == info["min_sdk"]
        assert str(tool_free["target_sdk"]) == info["target_sdk"]
        assert tool_free["permissions"] == ["android.permission.INTERNET"]
        # The launchable activity (entry point) the stdlib reader found from the
        # MAIN + LAUNCHER intent-filter must be the one androguard's own
        # get_main_activity resolves -- a second independent cross-check of the
        # entry-point fact, alongside the apktool gate's.
        assert tool_free["launcher_activity"] == info["main_activity"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.headless"
        assert "android.permission.INTERNET" in manifest.data["manifest_xml"]

        perms = service.apk_permissions(session_id)
        assert perms.ok, perms.error
        assert "android.permission.INTERNET" in perms.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == ["com.example.headless.MainActivity"]
        assert components.data["main_activity"] == "com.example.headless.MainActivity"

        certs = service.apk_certificates(session_id)
        assert certs.ok, certs.error
        assert certs.data["v1_signed"] is True
        assert len(certs.data["certificates"]) == 1
        assert certs.data["certificates"][0]["sha256"]

        libs = service.apk_native_libs(session_id)
        assert libs.ok, libs.error
        assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_apk_dex_analysis_happy_path() -> None:
    """androguard's full AnalyzeAPK path: the fixture carries a real one-class
    DEX, so classes/methods/strings/xrefs must return the analysed facts rather
    than a degradation envelope."""
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert "Lcom/example/headless/Sample;" in classes.data["classes"]

        # The stdlib DEX reader resolves the same defined class androguard does,
        # in dotted form (the descriptor Lcom/.../Sample; without its L...; wrap).
        tool_free = created.data["session"]["metadata"]["apk"]["dex"]["classes"]
        assert "com.example.headless.Sample" in tool_free

        methods = service.apk_methods(session_id, "com.example.headless.Sample")
        assert methods.ok, methods.error
        assert "getSecret" in [m["name"] for m in methods.data["methods"]]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert any("flag{headless-re}" in s for s in strings.data["strings"])

        # getSecret has no callers in this one-method DEX: the enumeration must
        # complete and say so, not error and not claim a phantom caller.
        xrefs = service.apk_xrefs(session_id, "getSecret")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["count"] == 0
        assert xrefs.data["has_more"] is False
    finally:
        service.close_all()
