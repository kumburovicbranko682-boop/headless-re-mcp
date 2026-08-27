"""Android deep static-analysis gate: the real androguard surface on a real APK.

Unlike ``test_android_re_gate`` (synthetic APK, degradation only), this runs the
whole ``apk.*`` toolchain against a committed, signed APK built from real Java
(``fixtures/android/`` + ``build.sh``): manifest facts, components, certificate,
DEX classes/methods/strings, and method cross-references. androguard is the only
requirement and it ships with the ``android`` extra, so a skip here means the
extra is genuinely absent -- skip != pass.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APK = _PROJECT_ROOT / "fixtures" / "android" / "sample.apk"
_PKG = "com.headlessre.sample"


@pytest.fixture()
def _service() -> Iterator[AnalysisService]:
    if not ApkClient().available:
        pytest.skip("androguard not installed — Android deep Gate not run (skip != pass)")
    if not _APK.is_file():
        pytest.skip(f"fixture missing: {_APK} (run fixtures/android/build.sh)")
    service = AnalysisService()
    try:
        yield service
    finally:
        service.close_all()


def _open_session(service: AnalysisService) -> str:
    created = service.create_session(str(_APK), target="apk")
    assert created.ok, created.error
    return str(created.data["session"]["id"])


@pytest.mark.integration
def test_manifest_facts_come_from_the_binary_axml(_service: AnalysisService) -> None:
    session_id = _open_session(_service)

    opened = _service.apk_open(session_id)
    assert opened.ok, opened.error
    assert opened.data["package"] == _PKG
    assert opened.data["version_name"] == "1.2.3"
    assert str(opened.data["version_code"]) == "7"
    assert set(opened.data["native_abis"]) == {"arm64-v8a", "x86_64"}

    perms = _service.apk_permissions(session_id)
    assert perms.ok, perms.error
    assert "android.permission.INTERNET" in perms.data["permissions"]
    assert "android.permission.ACCESS_NETWORK_STATE" in perms.data["permissions"]

    components = _service.apk_components(session_id)
    assert components.ok, components.error
    assert components.data["activities"] == [f"{_PKG}.MainActivity"]
    assert components.data["services"] == [f"{_PKG}.SyncService"]
    assert components.data["receivers"] == [f"{_PKG}.BootReceiver"]
    assert components.data["main_activity"] == f"{_PKG}.MainActivity"

    manifest = _service.apk_manifest(session_id)
    assert manifest.ok, manifest.error
    assert _PKG in manifest.data["manifest_xml"]


@pytest.mark.integration
def test_signature_and_native_libs_are_read(_service: AnalysisService) -> None:
    session_id = _open_session(_service)

    certs = _service.apk_certificates(session_id)
    assert certs.ok, certs.error
    assert certs.data["v1_signed"] is True
    assert len(certs.data["certificates"]) >= 1

    libs = _service.apk_native_libs(session_id)
    assert libs.ok, libs.error
    assert set(libs.data["abis"]) == {"arm64-v8a", "x86_64"}
    assert any(name.endswith("libsample.so") for name in libs.data["native_libs"])


@pytest.mark.integration
def test_dex_classes_methods_and_strings(_service: AnalysisService) -> None:
    session_id = _open_session(_service)

    classes = _service.apk_classes(session_id)
    assert classes.ok, classes.error
    names = set(classes.data["classes"])
    for short in ("MainActivity", "Crypto", "SyncService", "BootReceiver"):
        assert f"Lcom/headlessre/sample/{short};" in names, short

    methods = _service.apk_methods(session_id, f"{_PKG}.MainActivity")
    assert methods.ok, methods.error
    method_names = {item["name"] for item in methods.data["methods"]}
    assert {"secret", "run"} <= method_names

    strings = _service.apk_strings(session_id)
    assert strings.ok, strings.error
    assert "HEADLESS_RE_SECRET_TOKEN" in strings.data["strings"]


@pytest.mark.integration
def test_method_xrefs_follow_real_calls(_service: AnalysisService) -> None:
    session_id = _open_session(_service)

    # run() calls secret() and Crypto.transform(); both must name run as caller.
    secret_xrefs = _service.apk_xrefs(session_id, "secret")
    assert secret_xrefs.ok, secret_xrefs.error
    assert any(caller["method"] == "run" for caller in secret_xrefs.data["callers"])

    transform_xrefs = _service.apk_xrefs(session_id, "transform")
    assert transform_xrefs.ok, transform_xrefs.error
    assert any(caller["method"] == "run" for caller in transform_xrefs.data["callers"])


@pytest.mark.integration
def test_a_pe_only_tool_refuses_the_apk_session(_service: AnalysisService) -> None:
    session_id = _open_session(_service)
    refused = _service.open_static(session_id)
    assert refused.ok is False
    assert refused.error is not None
    assert refused.error.code in {"target_mismatch", "invalid_request", "backend_unavailable"}
