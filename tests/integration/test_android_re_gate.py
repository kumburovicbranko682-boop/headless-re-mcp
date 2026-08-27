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
        # not valid AXML, so open() must answer with a structured envelope rather
        # than raising. When it fails it has to be the clean, actionable
        # backend_error -- not internal_error, which would mean a raw androguard
        # KeyError leaked past the service's ApkError branch and minted an
        # incident for what is really an unparseable input.
        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        if not opened.ok:
            assert opened.error is not None
            assert opened.error.code == "backend_error", opened.error

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
def test_android_manifest_readers_never_leak_internal_error(tmp_path: Path) -> None:
    """Every manifest-level APK reader keeps its fault contract on hostile input.

    The synthetic APK carries a manifest that is not valid AXML, so androguard
    parses the archive but its accessors then raise deep inside the library. A
    reader that lets that escape reports internal_error (with an incident) for a
    plainly unparseable file, telling an unattended caller the tool broke rather
    than the input. Each reader must instead return either a real answer or a
    clean, actionable code. Runs on a bare machine: without androguard every
    reader degrades to capability_unavailable, which is also clean.
    """
    apk = _build_synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    clean_codes = {
        "backend_error",
        "capability_unavailable",
        "not_found",
        "invalid_params",
        "target_mismatch",
    }
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        readers = {
            "apk_open": service.apk_open,
            "apk_manifest": service.apk_manifest,
            "apk_permissions": service.apk_permissions,
            "apk_certificates": service.apk_certificates,
            "apk_components": service.apk_components,
            "apk_native_libs": service.apk_native_libs,
        }
        for name, call in readers.items():
            result = call(session_id)
            assert isinstance(result.ok, bool), name
            if not result.ok:
                assert result.error is not None, name
                assert result.error.code != "internal_error", (name, result.error)
                assert result.error.code in clean_codes, (name, result.error)
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
