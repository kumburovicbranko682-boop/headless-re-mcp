"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target


def _build_synthetic_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        # Minimal (not AXML-valid) manifest is enough for stdlib classification.
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("lib/x86_64/libnative.so", b"\x7fELFplaceholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return path


@pytest.mark.integration
def test_android_session_classification_and_metadata(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")

    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        meta = session["metadata"]["apk"]
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True

        session_id = session["id"]

        # androguard opens a real APK; on the synthetic archive its manifest is
        # not valid AXML, so apk.open must fail with a *structured* backend_error
        # -- androguard's constructor does not raise but leaves getters that do,
        # which used to fall through to the service's BaseException handler as an
        # internal_error with a logged incident (a bad APK misreported as a
        # server defect).
        opened = service.apk_open(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code == "backend_error"

        # Device enumeration degrades cleanly when adbutils / adb is absent.
        listed = service.device_list()
        assert isinstance(listed.ok, bool)
        assert listed.ok or listed.error is not None

        # Frida device enumeration returns an envelope (frida may be present).
        devices = service.frida_devices()
        assert isinstance(devices.ok, bool)
    finally:
        service.close_all()


@pytest.mark.integration
def test_malformed_apk_yields_structured_errors_not_incidents(tmp_path: Path) -> None:
    """A malformed APK is bad input, never a server defect.

    androguard is lenient: APK() does not raise on a broken manifest, so every
    apk.* method has to defend its own getters. Any that lets an androguard
    exception escape surfaces as internal_error with a logged incident, telling
    an unattended caller the server is broken when the sample is. Pin that none
    of them do that on the synthetic (invalid-AXML) archive.
    """
    from headless_re_mcp.backends.apk import ApkClient

    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static gate not run (skip != pass)")
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]
        calls = {
            "apk_open": lambda: service.apk_open(session_id),
            "apk_manifest": lambda: service.apk_manifest(session_id),
            "apk_permissions": lambda: service.apk_permissions(session_id),
            "apk_components": lambda: service.apk_components(session_id),
            "apk_native_libs": lambda: service.apk_native_libs(session_id),
            "apk_certificates": lambda: service.apk_certificates(session_id),
        }
        for name, call in calls.items():
            result = call()
            assert isinstance(result.ok, bool), name
            if not result.ok:
                assert result.error is not None, name
                assert result.error.code != "internal_error", (
                    f"{name} reported a malformed APK as a server incident"
                )
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_pe_tool_rejects_apk_session(tmp_path: Path) -> None:
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        # A PE-only tool must refuse an APK session with target_mismatch, not crash.
        opened = service.open_static(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code in {"target_mismatch", "invalid_request", "backend_unavailable"}
    finally:
        service.close_all()
