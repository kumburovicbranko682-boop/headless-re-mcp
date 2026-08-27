"""androguard APK gate: the apk.* static read surface end to end on Linux.

The existing Android gate (test_android_re_gate.py) builds a synthetic zip whose
AndroidManifest.xml is four bytes of fake AXML, so it only proves stdlib
classification and that apk.open returns *an envelope* -- it asserts
``opened.ok or opened.error is not None``, which a parse failure satisfies just
as well as a parse success. So the androguard surface that actually matters for
Android analysis -- reading a real package name, decoding binary AXML, listing
permissions/components, reading the signing certificate, enumerating native
ABIs, and walking the DEX for classes/methods/strings/xrefs -- had no test that
parses a real APK anywhere.

This gate reads a committed, tiny, v1-signed APK (fixtures/android/gate_fixture.apk,
built from the source tree beside it) and drives the whole apk.* read surface
through AnalysisService. The fixture is deliberate, not random: package
com.headlessre.gatefixture, two known permissions, an activity/service/receiver,
two native ABIs, and one class (MainActivity) whose getMarker() returns the
literal "headless-re apk gate fixture" and is called by onResume() -- so every
assertion checks recovered content, not just a non-empty envelope.

Real-tool tests skip with an explicit "skip != pass" when androguard is not
installed. The closed-session guard and the capability_unavailable degradation
test need no APK parse and always run. Verified against androguard 4.1.4 on
Linux.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# androguard 4.x logs a torrent of DEBUG lines through loguru on every parse;
# drop its sinks at import so the gate's own output stays readable. Guarded so
# the module still imports on a machine without androguard (hence without
# loguru), where the real-tool tests skip anyway.
try:
    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
except Exception:  # noqa: BLE001 - absence is fine; there is simply nothing to silence
    pass

from headless_re_mcp.backends.apk import ApkClient, ApkError
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "gate_fixture.apk"
_PACKAGE = "com.headlessre.gatefixture"
_MAIN_ACTIVITY = "com.headlessre.gatefixture.MainActivity"
_MAIN_CLASS = "Lcom/headlessre/gatefixture/MainActivity;"
_MARKER = "headless-re apk gate fixture"
_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
}


def _androguard_available() -> bool:
    return ApkClient().available


def _skip_without_androguard() -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — APK Gate not run (skip != pass)")


def _apk_session(service: AnalysisService) -> str:
    created = service.create_session(str(_APK_FIXTURE))
    assert created.ok, created.error
    assert created.data["session"]["target"] == "apk"
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_apk_open_reads_real_metadata() -> None:
    """apk.open recovers the package identity from binary AXML, not a guess.

    The synthetic-zip gate could never reach here: get_package() on four bytes
    of fake AXML returns nothing, which apk.open turns into backend_error. Real
    content means a real package name and version.
    """
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        data = opened.data
        assert data["opened"] is True
        assert data["package"] == _PACKAGE
        assert data["version_name"] == "1.0"
        assert str(data["version_code"]) == "1"
        assert str(data["min_sdk"]) == "21"
        assert str(data["target_sdk"]) == "33"
        assert data["main_activity"] == _MAIN_ACTIVITY
        assert data["permission_count"] == 2
        assert data["native_abis"] == ["arm64-v8a", "x86_64"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_manifest_decodes_binary_axml() -> None:
    """apk.manifest turns compiled AXML back into readable XML.

    The decoded text must name the package and the components declared in the
    source manifest; a failed AXML decode maps to backend_error instead.
    """
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        result = service.apk_manifest(session_id)
        assert result.ok, result.error
        assert result.data["package"] == _PACKAGE
        assert result.data["truncated"] is False
        xml = result.data["manifest_xml"]
        assert isinstance(xml, str) and xml.strip().startswith("<")
        assert _PACKAGE in xml
        assert "android.permission.INTERNET" in xml
        assert "MainActivity" in xml
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_permissions_and_components_list_manifest_entries() -> None:
    """permissions and components resolve every entry the manifest declares."""
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert set(permissions.data["permissions"]) == _PERMISSIONS
        assert set(permissions.data["requested_permissions"]) == _PERMISSIONS
        assert permissions.data["count"] == 2
        assert permissions.data["has_more"] is False

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert components.data["activities"] == [_MAIN_ACTIVITY]
        assert components.data["services"] == ["com.headlessre.gatefixture.GateService"]
        assert components.data["receivers"] == ["com.headlessre.gatefixture.GateReceiver"]
        assert components.data["providers"] == []
        assert components.data["main_activity"] == _MAIN_ACTIVITY
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_certificates_report_the_v1_signature() -> None:
    """apk.certificates reads the JAR (v1) signature the fixture was signed with.

    jarsigner added META-INF/*.RSA over a self-signed cert whose subject carries
    the fixture's name, so a correct read reports v1_signed with a fingerprint.
    """
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        result = service.apk_certificates(session_id)
        assert result.ok, result.error
        assert result.data["v1_signed"] is True
        assert any(name.endswith(".RSA") for name in result.data["signature_files"])
        assert result.data["certificates"], "no certificate parsed"
        cert = result.data["certificates"][0]
        assert "headless-re apk gate" in cert["subject"]
        # A SHA-256 fingerprint is 32 bytes; androguard renders it hex, so the
        # field must be present and non-trivial rather than the "" fallback.
        assert cert["sha256"] and len(cert["sha256"].replace(" ", "")) >= 32
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_native_libs_enumerate_abis() -> None:
    """apk.native_libs lists the committed .so files and derives their ABIs."""
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        result = service.apk_native_libs(session_id)
        assert result.ok, result.error
        assert result.data["native_libs"] == [
            "lib/arm64-v8a/libgate.so",
            "lib/x86_64/libgate.so",
        ]
        assert result.data["abis"] == ["arm64-v8a", "x86_64"]
        assert result.data["count"] == 2
        assert result.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_dex_surface_walks_classes_methods_strings_xrefs() -> None:
    """The DEX-analysis surface recovers the fixture's one real class.

    classes/methods/strings/xrefs all go through androguard's AnalyzeAPK, which
    the synthetic-zip gate never reaches. The fixture's MainActivity carries a
    known method (getMarker), a known string, and a known call edge
    (onResume -> getMarker), so each read is checked against real content.
    """
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert _MAIN_CLASS in classes.data["classes"]
        assert classes.data["total"] >= 1
        assert classes.data["scan_capped"] is False

        # Both the smali (L...;) and dotted forms must resolve the same class.
        for form in (_MAIN_CLASS, _PACKAGE + ".MainActivity"):
            methods = service.apk_methods(session_id, form)
            assert methods.ok, (form, methods.error)
            assert methods.data["class_name"] == _MAIN_CLASS
            names = {item["name"] for item in methods.data["methods"]}
            assert {"<init>", "getMarker", "onResume"} <= names, names

        strings = service.apk_strings(session_id)
        assert strings.ok, strings.error
        assert _MARKER in strings.data["strings"]

        xrefs = service.apk_xrefs(session_id, "getMarker")
        assert xrefs.ok, xrefs.error
        assert xrefs.data["count"] >= 1
        callers = {(c["class"], c["method"]) for c in xrefs.data["callers"]}
        assert (_MAIN_CLASS, "onResume") in callers
        assert xrefs.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_reads_reject_unknown_targets() -> None:
    """A missing class is not_found; an unreferenced method has zero callers."""
    _skip_without_androguard()
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)

        missing = service.apk_methods(session_id, "Lcom/does/not/Exist;")
        assert not missing.ok
        assert missing.error is not None
        assert missing.error.code == "not_found"

        # A real method name that nothing calls returns an empty, complete list
        # rather than an error: absence of callers is a fact, not a failure.
        constructor = service.apk_xrefs(session_id, "<init>")
        assert constructor.ok, constructor.error
        assert constructor.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_tools_refuse_a_closed_session() -> None:
    """The session-state guard fires before androguard is touched.

    Classification and the guard are stdlib-only, so this runs with or without
    androguard and pins the invalid_request mapping.
    """
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    service = AnalysisService()
    try:
        session_id = _apk_session(service)
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        refused = service.apk_open(session_id)
        assert not refused.ok
        assert refused.error is not None
        assert refused.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_degrades_when_androguard_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No androguard degrades to capability_unavailable, never a crash.

    Always runs: it swaps the service's ApkClient for one that reports the
    library missing, so even a machine with androguard installed exercises the
    absent-tool branch and proves the service maps it to capability_unavailable.
    """
    assert _APK_FIXTURE.is_file(), f"fixture missing: {_APK_FIXTURE}"

    class _NoAndroguardClient(ApkClient):
        def __init__(self) -> None:
            self._androguard = None
            self._available = False

    monkeypatch.setattr("headless_re_mcp.core.service_apk.ApkClient", _NoAndroguardClient)

    service = AnalysisService()
    try:
        session_id = _apk_session(service)

        opened = service.apk_open(session_id)
        assert not opened.ok
        assert opened.error is not None
        assert opened.error.code == "capability_unavailable"

        classes = service.apk_classes(session_id)
        assert not classes.ok
        assert classes.error is not None
        assert classes.error.code == "capability_unavailable"
    finally:
        service.close_all()


@pytest.mark.integration
def test_apk_client_reports_missing_file() -> None:
    """A path that does not exist is not_found, distinct from a parse failure."""
    _skip_without_androguard()

    client = ApkClient()
    missing = _APK_FIXTURE.parent / "definitely_absent.apk"
    with pytest.raises(ApkError) as caught:
        client.open(missing)
    assert caught.value.code == "not_found"
