"""APK manifest-side gate: apk.open / manifest / permissions / components.

The Android RE gate's synthetic APK has a placeholder manifest that is not valid
binary AXML, so androguard cannot parse it and the gate can only assert these
tools return a structured envelope without crashing -- it never checks a single
parsed value. That leaves the manifest surface (``APK.get_package`` /
``get_permissions`` / ``get_activities`` / ``get_android_manifest_axml`` ...)
unverified against a real manifest, the same runtime-only blind spot the DEX gate
closes for the analysis surface.

This gate uses the committed real APK (``fixtures/android/fixture.apk``, whose
manifest is genuine AXML compiled by apktool/aapt2) and drives the full
``AnalysisService`` stack, pinning the actual parsed package, SDK levels,
permission, and activity. Skips when the ``android`` extra is absent; skip is
not pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_APK = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "fixture.apk"


@pytest.mark.integration
def test_apk_manifest_side_over_a_real_manifest() -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK manifest Gate not run (skip != pass)")
    if not _FIXTURE_APK.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE_APK}")

    service = AnalysisService()
    try:
        created = service.create_session(str(_FIXTURE_APK))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # open: the package, version, and SDK levels must come back parsed from
        # the real AXML manifest, not just a non-crashing envelope.
        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == "com.example.fixture"
        assert opened.data["version_name"] == "1.0"
        assert opened.data["min_sdk"] == "21"
        assert opened.data["target_sdk"] == "30"
        assert opened.data["permission_count"] == 1
        # main_activity comes from get_main_activity(), which resolves the
        # LAUNCHER intent-filter -- a distinct, version-sensitive parse from the
        # activity enumeration below, and null unless a launcher is declared.
        assert opened.data["main_activity"] == "com.example.fixture.MainActivity"

        # manifest: decoding AXML back to XML must surface the package and the
        # declared permission.
        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.fixture"
        assert "android.permission.INTERNET" in manifest.data["manifest_xml"]

        # permissions: the requested permission is read out of <uses-permission>.
        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert "android.permission.INTERNET" in permissions.data["permissions"]

        # components: the declared activity is enumerated, and the launcher
        # activity is surfaced via the same intent-filter parse.
        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert "com.example.fixture.MainActivity" in components.data["activities"]
        assert components.data["main_activity"] == "com.example.fixture.MainActivity"

        # certificates: the fixture is unsigned, so this must degrade to a clean
        # empty result rather than raising.
        certificates = service.apk_certificates(session_id)
        assert certificates.ok, certificates.error
        assert certificates.data["v1_signed"] is False
    finally:
        service.close_all()
