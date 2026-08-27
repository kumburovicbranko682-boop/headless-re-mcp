"""Android RE gate: session classification, APK metadata, and safe degradation.

Runs without a device or extra tools by building APKs in a temp dir. A
deliberately invalid archive proves classification, stdlib metadata, and safe
degradation on a bare machine; a second, genuinely androguard-parseable APK
(real binary manifest plus a real compiled ``classes.dex``, built by
``_apk_fixture``) exercises the androguard success path -- package, version,
permissions, every component type, and the DEX code surface (classes, methods,
strings, xrefs) -- skipping only where the ``android`` extra is absent. Parts
that need a real device / jadx / adbutils are asserted only for a structured
envelope, never a crash (skip != pass for the live-device parts).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from _apk_fixture import EXPECTED, build_valid_apk

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
def test_android_static_reads_a_real_manifest(tmp_path: Path) -> None:
    """Exercise the androguard success path against a real binary manifest.

    The synthetic-APK test above only proves the adapter degrades on garbage.
    This one hands androguard a valid AXML manifest and asserts it reads the
    package, version, permissions, and every component type back out -- the path
    that silently breaks when androguard renames an accessor between releases.
    Skips (skip != pass) where the ``android`` extra is not installed.
    """
    pytest.importorskip("androguard")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == EXPECTED["package"]
        assert str(opened.data["version_name"]) == EXPECTED["version_name"]
        assert str(opened.data["version_code"]) == EXPECTED["version_code"]
        assert opened.data["main_activity"] == EXPECTED["main_activity"]
        assert opened.data["permission_count"] == len(EXPECTED["permissions"])
        assert set(opened.data["native_abis"]) == EXPECTED["native_abis"]

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert set(permissions.data["permissions"]) == EXPECTED["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert set(components.data["activities"]) == EXPECTED["activities"]
        assert set(components.data["services"]) == EXPECTED["services"]
        assert set(components.data["receivers"]) == EXPECTED["receivers"]
        assert set(components.data["providers"]) == EXPECTED["providers"]
        assert components.data["main_activity"] == EXPECTED["main_activity"]

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert set(native.data["abis"]) == EXPECTED["native_abis"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert EXPECTED["package"] in manifest.data["manifest_xml"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_static_reads_dex_code(tmp_path: Path) -> None:
    """Exercise androguard's DEX analysis against a real compiled classes.dex.

    The manifest test above proves the resource surface; this one proves the
    code surface -- the path that needs a genuine DEX and that mocked unit tests
    (which stub androguard's analysis) cannot reach. It asserts the class, its
    methods, an embedded string, and an intra-DEX xref (run -> greet) all read
    back out. Skips (skip != pass) where the ``android`` extra is not installed.
    """
    pytest.importorskip("androguard")
    apk = build_valid_apk(tmp_path / "hello.apk")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert EXPECTED["dex_class"] in classes.data["classes"]

        methods = service.apk_methods(session_id, EXPECTED["dex_class"])
        assert methods.ok, methods.error
        assert {m["name"] for m in methods.data["methods"]} == EXPECTED["dex_methods"]

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert any(EXPECTED["dex_string"] in s for s in strings.data["strings"]), (
            strings.data["strings"]
        )

        # run() calls greet(); androguard must see that intra-DEX cross-reference.
        xrefs = service.apk_xrefs(session_id, EXPECTED["dex_xref_target"])
        assert xrefs.ok, xrefs.error
        callers = {(c["class"], c["method"]) for c in xrefs.data["callers"]}
        assert (EXPECTED["dex_class"], EXPECTED["dex_xref_caller"]) in callers, xrefs.data
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
