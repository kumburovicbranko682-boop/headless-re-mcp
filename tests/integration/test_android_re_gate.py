"""Android RE gate: session classification, real APK static analysis, safe degradation.

The static surface runs against a committed, genuinely parseable fixture
(``fixtures/android/gate.apk``: a binary AndroidManifest.xml plus a hand-built
DEX with a class, two methods, a referenced string constant, and a real
method-to-method xref). That is the point of this gate -- it used to build a
synthetic archive that androguard cannot parse and then accept ``apk.open``
returning *either* success or an error, so the entire androguard code path could
break and the gate would stay green. Now every field the backend extracts is
asserted against a known value, so a regression in the manifest or DEX reader
fails here.

androguard is a pure-Python dependency (the ``android`` extra), so the static
tests run wherever it is installed -- the ``linux-android-static`` CI job does,
and skips explicitly when it is absent so a skip never reads as a pass. The
device / Frida parts need real hardware and only assert a structured envelope,
never a crash.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "gate.apk"

_SECRET_CLASS = "Lcom/example/gate/Secret;"


def _require_apk_fixture() -> Path:
    assert _APK_FIXTURE.is_file(), (
        f"fixture missing: {_APK_FIXTURE} — regenerate with "
        "python fixtures/android/build_gate_apk.py"
    )
    return _APK_FIXTURE


def _require_androguard() -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed — APK static Gate not run (skip != pass)")


@pytest.mark.integration
def test_android_session_classification_and_metadata() -> None:
    """Classification and the stdlib metadata read work without androguard."""
    apk = _require_apk_fixture()
    assert classify_target(apk) is TargetKind.APK

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "apk"
        meta = session["metadata"]["apk"]
        # describe_apk reads the zip directory only (no androguard): ABIs from
        # lib/<abi>/, dex count, and a v1 signature file under META-INF.
        assert set(meta["native_abis"]) == {"arm64-v8a", "x86_64"}
        assert meta["dex_count"] == 1
        assert meta["signed_v1"] is True

        # Device enumeration degrades cleanly when adbutils / adb is absent; it
        # never crashes, but a live device is not required for this gate.
        listed = service.device_list()
        assert isinstance(listed.ok, bool)
        assert listed.ok or listed.error is not None

        # Frida device enumeration returns an envelope (frida may be present).
        devices = service.frida_devices()
        assert isinstance(devices.ok, bool)
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_static_surface_against_a_real_apk() -> None:
    """Every androguard-backed apk.* op returns the known contents of the fixture.

    This is the coverage the old "ok or error" assertion never gave: the whole
    stack from session routing through the androguard backend to the result
    envelope, checked against values the fixture encodes on purpose.
    """
    apk = _require_apk_fixture()
    _require_androguard()

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        info = opened.data
        assert info["opened"] is True
        assert info["package"] == "com.example.gate"
        assert info["version_name"] == "1.2.3"
        assert str(info["version_code"]) == "7"
        assert str(info["min_sdk"]) == "21"
        assert str(info["target_sdk"]) == "33"
        assert info["main_activity"] == "com.example.gate.MainActivity"
        assert info["permission_count"] == 2
        assert info["native_abis"] == ["arm64-v8a", "x86_64"]

        manifest = service.apk_manifest(session_id)
        assert manifest.ok, manifest.error
        assert manifest.data["package"] == "com.example.gate"
        # The decoded AXML must be real XML naming the package and a component.
        xml = manifest.data["manifest_xml"]
        assert "com.example.gate" in xml
        assert "MainActivity" in xml
        assert manifest.data["truncated"] is False

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert permissions.data["permissions"] == [
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ]
        assert permissions.data["count"] == 2
        assert permissions.data["has_more"] is False

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == ["com.example.gate.MainActivity"]
        assert components.data["services"] == ["com.example.gate.BgService"]
        assert components.data["main_activity"] == "com.example.gate.MainActivity"

        native = service.apk_native_libs(session_id)
        assert native.ok, native.error
        assert native.data["abis"] == ["arm64-v8a", "x86_64"]
        assert native.data["native_libs"] == [
            "lib/arm64-v8a/libnative.so",
            "lib/x86_64/libnative.so",
        ]

        # The placeholder signature is not a valid v1 block, so androguard finds
        # no certificates; the op must still answer a well-formed envelope
        # rather than raising -- that is what the gate pins here.
        certificates = service.apk_certificates(session_id)
        assert certificates.ok, certificates.error
        assert isinstance(certificates.data["certificates"], list)
        assert isinstance(certificates.data["signature_files"], list)
        assert isinstance(certificates.data["v1_signed"], bool)

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert classes.data["classes"] == [_SECRET_CLASS]
        assert classes.data["total"] == 1
        assert classes.data["has_more"] is False

        methods = service.apk_methods(session_id, _SECRET_CLASS)
        assert methods.ok, methods.error
        by_name = {m["name"]: m for m in methods.data["methods"]}
        assert set(by_name) == {"caller", "decrypt"}
        assert by_name["decrypt"]["descriptor"] == "()Ljava/lang/String;"
        assert "static" in by_name["decrypt"]["access"]

        # A page smaller than the method count must report has_more and clamp
        # the window -- the same pagination contract the unit tests pin on mocks.
        first = service.apk_methods(session_id, _SECRET_CLASS, offset=0, limit=1)
        assert first.ok, first.error
        assert first.data["count"] == 1
        assert first.data["total"] == 2
        assert first.data["has_more"] is True

        strings = service.apk_strings(session_id, limit=2000)
        assert strings.ok, strings.error
        assert "gate-secret-string" in strings.data["strings"]

        # decrypt is invoked by caller, so it has exactly one real xref-from.
        xrefs = service.apk_xrefs(session_id, "decrypt")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["callers"] == [{"class": _SECRET_CLASS, "method": "caller"}]
        assert xrefs.data["has_more"] is False

        # A method nobody calls resolves cleanly to an empty, complete caller
        # list -- not an error, not a partial answer.
        none = service.apk_xrefs(session_id, "caller")
        assert none.ok, none.error
        assert none.data["callers"] == []
        assert none.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_methods_missing_class_is_a_structured_not_found() -> None:
    """A class the DEX does not define is reported, not raised as a crash."""
    apk = _require_apk_fixture()
    _require_androguard()

    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        session_id = created.data["session"]["id"]
        missing = service.apk_methods(session_id, "Lcom/example/gate/DoesNotExist;")
        assert missing.ok is False
        assert missing.error is not None
        assert missing.error.code == "not_found"
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_pe_tool_rejects_apk_session() -> None:
    apk = _require_apk_fixture()
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
