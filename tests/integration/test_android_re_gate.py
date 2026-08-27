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

        # androguard opens a real APK; the synthetic archive is a real zip whose
        # AndroidManifest.xml is not valid AXML, so androguard's parse fails. That
        # must surface as a structured backend_error -- never a raised exception,
        # and never an internal_error carrying an error-boundary incident, which
        # would read as an adapter bug for what is only the caller's corrupt input
        # (capability_unavailable is also fine when androguard is not installed).
        opened = service.apk_open(session_id)
        assert opened.ok is False
        assert opened.error is not None
        assert opened.error.code in {"backend_error", "capability_unavailable"}, opened.error.code
        assert "incident_id" not in (opened.error.details or {})

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
def test_android_apk_ops_degrade_without_incident_on_a_hostile_manifest(tmp_path: Path) -> None:
    """No androguard apk.* op may crash or mint an internal_error on bad input.

    A file that classifies as an APK (a real zip carrying an AndroidManifest.xml
    entry) whose manifest is not valid AXML is routine corrupt/hostile input for
    an unattended agent. androguard's APK() fails to parse it, and the getters
    react differently: some raise internally (surfaced as backend_error), some
    return best-effort results because they read the zip rather than the manifest
    (native_libs, certificates, components, permissions). Either is fine. What
    must never happen is a raised exception reaching the caller, or a failure
    landing as internal_error with an error-boundary incident -- that would read
    as an adapter bug for what is only the caller's corrupt data. apk.open pins
    this for one op above; this pins the rest of the androguard surface (verified
    against androguard 4.1.4) so a regression that starts leaking a raw exception
    through the service's BaseException catch-all fails here.
    """
    apk = _build_synthetic_apk(tmp_path / "hostile.apk")
    service = AnalysisService()
    try:
        session_id = service.create_session(str(apk)).data["session"]["id"]
        klass = "Lcom/example/Foo;"
        # Building this dict calls every op; a raise (rather than a returned
        # Result) aborts here and fails the test, which is the crash guard.
        results = {
            "manifest": service.apk_manifest(session_id),
            "permissions": service.apk_permissions(session_id),
            "certificates": service.apk_certificates(session_id),
            "components": service.apk_components(session_id),
            "native_libs": service.apk_native_libs(session_id),
            "classes": service.apk_classes(session_id),
            "methods": service.apk_methods(session_id, klass),
            "strings": service.apk_strings(session_id),
            "xrefs": service.apk_xrefs(session_id, f"{klass}->bar()V"),
        }
        for name, result in results.items():
            if result.ok:
                continue  # best-effort success is allowed; only failures are pinned
            assert result.error is not None, name
            assert result.error.code != "internal_error", (name, result.error.code)
            assert result.error.code in {"backend_error", "capability_unavailable"}, (
                name,
                result.error.code,
            )
            assert "incident_id" not in (result.error.details or {}), name
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
