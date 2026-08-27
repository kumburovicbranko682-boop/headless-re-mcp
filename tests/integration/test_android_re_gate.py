"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building a synthetic (harmless) APK in
a temp dir. Parts that need a real device / jadx / adbutils are asserted only
for a structured envelope, never a crash, so the gate is meaningful on a bare
machine while still exercising the Android surface end to end (skip != pass for
the live-device parts, which have their own explicit skips).

The success-path test additionally builds a *valid* APK (binary AXML manifest
plus a real one-class DEX, generated in pure Python by
``fixtures/android/apk_fixture.py``) and asserts androguard actually returns
the manifest facts, components, classes, methods, strings and xrefs it was
given -- the surface the placeholder-zip tests can only prove "does not crash".
"""

from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_FIXTURE_BUILDER = Path(__file__).resolve().parents[2] / "fixtures" / "android" / "apk_fixture.py"


def _load_fixture_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("apk_fixture", _FIXTURE_BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

        # androguard opens a real APK; on the synthetic archive it must still
        # answer with a structured envelope rather than raising.
        opened = service.apk_open(session_id)
        assert isinstance(opened.ok, bool)
        assert opened.ok or opened.error is not None

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
def test_apk_static_success_path_on_generated_valid_apk(tmp_path: Path) -> None:
    """androguard must return the facts the generated APK was built with.

    Every assertion below targets a value ``fixtures/android/apk_fixture.py``
    encoded into the AXML manifest or the DEX, so a pass means the parse
    pipeline (APK -> AXML decode, AnalyzeAPK -> class/method/string/xref
    analysis) genuinely worked, not merely that an envelope came back.
    """
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static Gate not run (skip != pass)")
    fx = _load_fixture_builder()
    apk = fx.build_apk(tmp_path / "gate.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        assert created.data["session"]["target"] == "apk"

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == fx.PACKAGE
        assert opened.data["version_code"] == str(fx.VERSION_CODE)
        assert opened.data["version_name"] == fx.VERSION_NAME
        assert opened.data["min_sdk"] == str(fx.MIN_SDK)
        assert opened.data["target_sdk"] == str(fx.TARGET_SDK)
        assert opened.data["main_activity"] == fx.MAIN_ACTIVITY
        assert opened.data["native_abis"] == ["arm64-v8a"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == fx.PACKAGE
        assert fx.PERMISSION in manifest.data["manifest_xml"]
        assert manifest.data["truncated"] is False

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert permissions.data["permissions"] == [fx.PERMISSION]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == [fx.MAIN_ACTIVITY]
        assert components.data["services"] == [fx.SERVICE]
        assert components.data["receivers"] == [fx.RECEIVER]
        assert components.data["providers"] == [fx.PROVIDER]
        assert components.data["main_activity"] == fx.MAIN_ACTIVITY

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert native.data["native_libs"] == [fx.NATIVE_LIB]
        assert native.data["abis"] == ["arm64-v8a"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == [fx.CLASS_SMALI]

        # Both the smali and the dotted spelling must resolve the class.
        for spelling in (fx.CLASS_SMALI, fx.CLASS_DOTTED):
            methods = service.apk_methods(session_id, spelling)
            assert methods.ok, methods.error
            names = {m["name"] for m in methods.data["methods"]}
            assert names == {fx.METHOD_ENTRY, fx.METHOD_LEAF}

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert fx.STRING_PAYLOAD in strings.data["strings"]

        # entry() calls leaf() via invoke-static in the DEX bytecode; xref
        # analysis must recover exactly that caller.
        xrefs = service.apk_xrefs(session_id, fx.METHOD_LEAF)
        assert xrefs.ok, xrefs.error
        assert {"class": fx.CLASS_SMALI, "method": fx.METHOD_ENTRY} in xrefs.data["callers"]
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
