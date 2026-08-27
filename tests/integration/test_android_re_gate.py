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

        # androguard opens a real APK; on the synthetic archive its manifest
        # does not parse, and every read must answer with a *structured*
        # envelope. Not merely "an error": a raw getter exception (a bare
        # KeyError from walking the unparsed manifest) used to reach the
        # service as internal_error with a logged incident, casting a property
        # of the input file as a server defect. The read failing is fine; the
        # read minting an incident is the regression this guards.
        for read in (
            service.apk_open,
            service.apk_manifest,
            service.apk_permissions,
            service.apk_certificates,
            service.apk_components,
            service.apk_native_libs,
        ):
            result = read(session_id)
            assert isinstance(result.ok, bool)
            if not result.ok:
                assert result.error is not None
                assert result.error.code != "internal_error", (
                    f"{read.__name__} filed a malformed APK as an internal incident: "
                    f"{result.error.message}"
                )

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
def test_device_control_of_a_missing_device_is_structured_not_internal() -> None:
    """Every serial-taking ADB op must fail structured when no device is there.

    An unattended agent routinely pokes a device that is offline or was never
    attached. Whether adb is missing (capability_unavailable) or present with
    no device (a transport backend_error), the envelope must be a deliberate
    code -- never internal_error, which files a property of the environment as
    a server defect and mints an incident. Only device_list was guarded before;
    the serial ops, the ones an agent actually drives, were not.
    """
    service = AnalysisService()
    bogus = "no-such-device:5555"
    try:
        ops = (
            ("device_info", lambda: service.device_info(bogus)),
            ("device_properties", lambda: service.device_properties(bogus)),
            ("device_packages", lambda: service.device_packages(bogus)),
            ("device_current_activity", lambda: service.device_current_activity(bogus)),
            ("device_logcat", lambda: service.device_logcat(bogus)),
            ("device_launch", lambda: service.device_launch(bogus, "com.example.app")),
            ("device_force_stop", lambda: service.device_force_stop(bogus, "com.example.app")),
            ("device_uninstall", lambda: service.device_uninstall(bogus, "com.example.app")),
            ("device_screenshot", lambda: service.device_screenshot(bogus)),
            ("device_pull", lambda: service.device_pull(bogus, "/data/local/tmp/x")),
        )
        for name, call in ops:
            result = call()
            assert result.ok is False, f"{name} unexpectedly succeeded against a missing device"
            assert result.error is not None
            assert result.error.code != "internal_error", (
                f"{name} filed a missing device as an internal incident: {result.error.message}"
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
