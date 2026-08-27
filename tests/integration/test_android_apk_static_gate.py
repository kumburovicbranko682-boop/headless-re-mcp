"""Android static gate: androguard's real parse path on a committed APK.

The sibling ``test_android_re_gate`` builds a synthetic archive whose manifest
is not valid AXML, so it can only prove the backend *degrades* cleanly. Nothing
exercised androguard's happy path -- the package, versions, permissions,
components, certificate, and native ABIs a real capture depends on -- so a
regression in that extraction would pass CI unseen. This gate consumes a
committed, v1-signed minimal APK (see fixtures/android/build_minimal_apk.py)
and asserts the extracted facts. skip != pass: it skips only when androguard is
not installed, and says so.
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
def test_android_apk_dex_tools_degrade_on_placeholder_dex() -> None:
    """The fixture's classes.dex is a placeholder, so DEX analysis must return a
    structured envelope, never crash -- the same contract the synthetic gate
    checks, but here alongside a manifest that really parses."""
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    if not _androguard_available():
        pytest.skip("androguard not installed — static gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE))
        session_id = created.data["session"]["id"]
        classes = service.apk_classes(session_id)
        assert isinstance(classes.ok, bool)
        assert classes.ok or classes.error is not None
    finally:
        service.close_all()
