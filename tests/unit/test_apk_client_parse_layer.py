"""Parse-layer and guard-path coverage for the APK client.

The apk.* field tests monkeypatch ``_apk``/``_parsed`` with fakes, so the real
androguard-backed layer -- availability, ``_require``, the mtime-keyed light and
full caches, and ``_ParsedApk`` -- was never exercised, and neither were the
per-listing guard arcs (an older androguard without requested permissions, a
signing block that will not enumerate, a certificate that will not render, a
top-level ``lib/`` entry with no ABI, an external class skipped, a blank/absent
class or method).

androguard is optional and not installed in this environment, so a tiny fake
``androguard`` package is installed into ``sys.modules`` to drive the import the
client does lazily. Nothing here needs a real APK parser; the fake returns
sentinels and the tests assert the client's own caching and error mapping.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import headless_re_mcp.backends.apk.client as apk_mod
from headless_re_mcp.backends.apk.client import (
    _MAX_CERTIFICATES,
    ApkClient,
    ApkError,
    _dotted_to_smali,
    _ParsedApk,
)


@pytest.fixture(autouse=True)
def _clear_caches() -> Any:
    """The caches are process-wide class state; keep tests independent."""
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _install_androguard(
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk_factory: Any = None,
    analyze_factory: Any = None,
) -> None:
    """Install a minimal fake ``androguard`` package for the lazy imports."""
    root = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    core_apk = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    core_apk.APK = apk_factory or (lambda path: MagicMock(name="APK"))  # type: ignore[attr-defined]
    misc.AnalyzeAPK = analyze_factory or (  # type: ignore[attr-defined]
        lambda path: (MagicMock(name="apk"), MagicMock(name="dex"), MagicMock(name="analysis"))
    )
    root.core = core  # type: ignore[attr-defined]
    core.apk = core_apk  # type: ignore[attr-defined]
    root.misc = misc  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", root)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.apk", core_apk)
    monkeypatch.setitem(sys.modules, "androguard.misc", misc)


def _apk_file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04")
    return path


# --- availability ------------------------------------------------------------


def test_available_is_true_when_androguard_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_androguard(monkeypatch)
    assert ApkClient().available is True


def test_available_is_false_when_androguard_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the lazy ``import androguard`` to fail rather than leaning on the
    # ambient environment happening to lack the optional extra: ``None`` in
    # sys.modules makes the import raise ImportError. Without this the test
    # turned red the moment someone installed ``.[android]`` and ran the suite.
    monkeypatch.setitem(sys.modules, "androguard", None)
    assert ApkClient().available is False


# --- _require ----------------------------------------------------------------


def test_require_reports_capability_unavailable_without_androguard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "androguard", None)
    client = ApkClient()  # available False
    with pytest.raises(ApkError) as caught:
        client.open(_apk_file(tmp_path))
    assert caught.value.code == "capability_unavailable"


def test_require_reports_a_missing_apk_as_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client.open(tmp_path / "gone.apk")
    assert caught.value.code == "not_found"


# --- _apk (light cache) ------------------------------------------------------


def test_apk_parses_once_then_serves_the_light_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second call for the same path/mtime returns the cached parse."""
    calls: list[str] = []
    sentinel = object()

    def apk_factory(path: str) -> Any:
        calls.append(path)
        return sentinel

    _install_androguard(monkeypatch, apk_factory=apk_factory)
    client = ApkClient()
    apk = _apk_file(tmp_path)

    first = client._apk(apk)
    second = client._apk(apk)

    assert first is sentinel
    assert second is sentinel
    assert len(calls) == 1


def test_apk_parse_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def apk_boom(path: str) -> Any:
        raise ValueError("not a zip")

    _install_androguard(monkeypatch, apk_factory=apk_boom)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._apk(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"
    assert "failed to parse APK" in caught.value.message


def test_apk_light_cache_evicts_the_oldest_past_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch, apk_factory=lambda path: object())
    client = ApkClient()
    files = [_apk_file(tmp_path, f"app{i}.apk") for i in range(apk_mod._CACHE_LIMIT + 1)]
    for apk in files:
        client._apk(apk)
    assert len(ApkClient._light_cache) == apk_mod._CACHE_LIMIT
    oldest = str(files[0].resolve())
    assert not any(key[0] == oldest for key in ApkClient._light_cache)


# --- _parsed (full cache) ----------------------------------------------------


def test_parsed_analyzes_once_then_serves_the_full_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    apk_obj, dex_obj, analysis_obj = object(), object(), object()

    def analyze_factory(path: str) -> Any:
        calls.append(path)
        return (apk_obj, dex_obj, analysis_obj)

    _install_androguard(monkeypatch, analyze_factory=analyze_factory)
    client = ApkClient()
    apk = _apk_file(tmp_path)

    first = client._parsed(apk)
    second = client._parsed(apk)

    assert first is second
    assert first.apk is apk_obj
    assert first.analysis is analysis_obj
    assert len(calls) == 1


def test_parsed_analysis_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def analyze_boom(path: str) -> Any:
        raise RuntimeError("dex blew up")

    _install_androguard(monkeypatch, analyze_factory=analyze_boom)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._parsed(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"
    assert "failed to analyze APK" in caught.value.message


def test_parsed_full_cache_evicts_the_oldest_past_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch, analyze_factory=lambda path: (object(), object(), object()))
    client = ApkClient()
    files = [_apk_file(tmp_path, f"a{i}.apk") for i in range(apk_mod._CACHE_LIMIT + 1)]
    for apk in files:
        client._parsed(apk)
    assert len(ApkClient._full_cache) == apk_mod._CACHE_LIMIT


# --- release -----------------------------------------------------------------


def test_release_returns_false_when_the_path_cannot_be_resolved() -> None:
    """A path whose resolve() raises OSError is a no-op, not a crash."""
    broken = MagicMock()
    broken.expanduser.return_value.resolve.side_effect = OSError("bad path")
    assert ApkClient.release(broken) is False


# --- listing guard branches (fakes injected on the instance) -----------------


def _client_with_apk(apk: Any) -> ApkClient:
    client = ApkClient()
    client._apk = lambda path: apk  # type: ignore[method-assign]
    return client


def _client_with_parsed(analysis: Any) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda path: _ParsedApk(apk=None, analysis=analysis, dex=None)  # type: ignore[method-assign]
    return client


def test_manifest_decode_failure_is_a_backend_error(tmp_path: Path) -> None:
    class Apk:
        def get_android_manifest_axml(self) -> Any:
            raise RuntimeError("axml broken")

    with pytest.raises(ApkError) as caught:
        _client_with_apk(Apk()).manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"
    assert "failed to decode manifest" in caught.value.message


def test_permissions_falls_back_when_requested_permissions_is_unavailable(
    tmp_path: Path,
) -> None:
    """Older androguard has no get_requested_permissions; fall back to declared."""

    class Apk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET"]

        def get_requested_permissions(self) -> Any:
            raise AttributeError("older androguard")

    payload = _client_with_apk(Apk()).permissions(tmp_path / "app.apk")
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["requested_permissions"] == ["android.permission.INTERNET"]


def test_certificates_when_the_signing_block_will_not_enumerate(tmp_path: Path) -> None:
    """get_signature_names raising means no v1 signature, not a crash."""

    class Apk:
        def get_signature_names(self) -> Any:
            raise RuntimeError("no signing block")

        def get_certificates(self) -> list[Any]:
            return []

    payload = _client_with_apk(Apk()).certificates(tmp_path / "app.apk")
    assert payload["signature_files"] == []
    assert payload["certificates"] == []
    assert payload["v1_signed"] is False
    assert payload["has_more"] is False


def test_certificates_caps_both_signature_files_and_certs(tmp_path: Path) -> None:
    class Cert:
        subject = "CN=test"
        issuer = "CN=test"
        serial_number = 1
        sha256_fingerprint = "ab"

    class Apk:
        def get_signature_names(self) -> list[str]:
            return [f"META-INF/CERT{i}.RSA" for i in range(_MAX_CERTIFICATES + 8)]

        def get_certificates(self) -> list[Any]:
            return [Cert() for _ in range(_MAX_CERTIFICATES + 8)]

    payload = _client_with_apk(Apk()).certificates(tmp_path / "app.apk")
    assert len(payload["signature_files"]) == _MAX_CERTIFICATES
    assert len(payload["certificates"]) == _MAX_CERTIFICATES
    assert payload["has_more"] is True


def test_certificates_skips_a_cert_that_will_not_render(tmp_path: Path) -> None:
    class GoodCert:
        subject = "CN=ok"
        issuer = "CN=ok"
        serial_number = 7
        sha256_fingerprint = "cd"

    class BadCert:
        @property
        def subject(self) -> str:
            raise RuntimeError("cert object from a different androguard")

    class Apk:
        def get_signature_names(self) -> list[str]:
            return ["META-INF/CERT.RSA"]

        def get_certificates(self) -> list[Any]:
            return [GoodCert(), BadCert()]

    payload = _client_with_apk(Apk()).certificates(tmp_path / "app.apk")
    assert len(payload["certificates"]) == 1
    assert payload["certificates"][0]["subject"] == "CN=ok"


def test_native_libs_keeps_a_top_level_lib_entry_without_an_abi(tmp_path: Path) -> None:
    """``lib/foo.so`` has no ABI segment; it is still a native lib, no ABI added."""

    class Apk:
        def get_files(self) -> list[str]:
            return ["lib/arm64-v8a/libx.so", "lib/toplevel.so", "classes.dex"]

    payload = _client_with_apk(Apk()).native_libs(tmp_path / "app.apk")
    assert payload["count"] == 2
    assert payload["abis"] == ["arm64-v8a"]


def test_classes_skips_external_classes(tmp_path: Path) -> None:
    class Klass:
        def __init__(self, name: str, external: bool) -> None:
            self.name = name
            self._external = external

        def is_external(self) -> bool:
            return self._external

    class Analysis:
        def get_classes(self) -> list[Any]:
            return [Klass("Lext;", True), Klass("Lapp/Main;", False)]

    payload = _client_with_parsed(Analysis()).classes(tmp_path / "app.apk")
    assert payload["classes"] == ["Lapp/Main;"]


def test_methods_requires_a_class_name(tmp_path: Path) -> None:
    class Analysis:
        def get_classes(self) -> list[Any]:
            return []

    with pytest.raises(ApkError) as caught:
        _client_with_parsed(Analysis()).methods(tmp_path / "app.apk", "   ")
    assert caught.value.code == "invalid_params"


def test_methods_reports_an_unknown_class_as_not_found(tmp_path: Path) -> None:
    class Analysis:
        def get_classes(self) -> list[Any]:
            return []

    with pytest.raises(ApkError) as caught:
        _client_with_parsed(Analysis()).methods(tmp_path / "app.apk", "com.absent.Type")
    assert caught.value.code == "not_found"


def test_xrefs_requires_a_method_name(tmp_path: Path) -> None:
    class Analysis:
        def get_methods(self) -> list[Any]:
            return []

    with pytest.raises(ApkError) as caught:
        _client_with_parsed(Analysis()).xrefs(tmp_path / "app.apk", "  ")
    assert caught.value.code == "invalid_params"


def test_xrefs_skips_external_and_mismatched_methods(tmp_path: Path) -> None:
    class Call:
        class_name = "Lcom/caller;"
        name = "invoke"

    class Method:
        def __init__(self, name: str, external: bool, callers: int) -> None:
            self.name = name
            self._external = external
            self._callers = callers

        def is_external(self) -> bool:
            return self._external

        def get_xref_from(self) -> list[Any]:
            return [(None, Call(), None) for _ in range(self._callers)]

    class Analysis:
        def get_methods(self) -> list[Any]:
            return [
                Method("target", True, 5),  # external: skipped
                Method("other", False, 5),  # name mismatch: skipped
                Method("target", False, 2),  # the real one
            ]

    payload = _client_with_parsed(Analysis()).xrefs(tmp_path / "app.apk", "target")
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_dotted_to_smali_passes_through_an_already_smali_name() -> None:
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
