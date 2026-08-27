"""Plumbing- and error-branch tests for the androguard APK client.

androguard is an optional dependency and is absent here, so the parse/cache
helpers (``_require``, ``_apk``, ``_parsed``) and the availability import never
run in the field tests, which stub ``_apk``/``_parsed`` outright. This file
injects a minimal fake ``androguard`` into ``sys.modules`` to drive the real
cache miss/hit/evict and parse-failure arcs, and fakes the APK/analysis objects
to reach the manifest/permission/certificate error branches and the class,
method, and xref guards.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError, _dotted_to_smali, _ParsedApk


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _install_fake_androguard(
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk_cls: Any = None,
    analyze: Any = None,
) -> None:
    package = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    core_apk = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    core_apk.APK = apk_cls  # type: ignore[attr-defined]
    misc.AnalyzeAPK = analyze  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", package)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.apk", core_apk)
    monkeypatch.setitem(sys.modules, "androguard.misc", misc)


def _apk_file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04")
    return path


# --- availability + _require guards -----------------------------------------


def test_require_reports_unavailable_without_androguard(tmp_path: Path) -> None:
    client = ApkClient()  # androguard is not installed in the test environment
    assert client.available is False
    with pytest.raises(ApkError) as exc:
        client._require(_apk_file(tmp_path))
    assert exc.value.code == "capability_unavailable"


def test_require_reports_missing_file(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as exc:
        client._require(tmp_path / "absent.apk")
    assert exc.value.code == "not_found"


def test_release_returns_false_on_unresolvable_path() -> None:
    class _BadPath:
        def expanduser(self) -> _BadPath:
            return self

        def resolve(self) -> Path:
            raise OSError("cannot resolve")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


# --- _apk light-cache plumbing ----------------------------------------------


def test_apk_light_cache_parses_once_then_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[str] = []

    class _APK:
        def __init__(self, path: str) -> None:
            built.append(path)

    _install_fake_androguard(monkeypatch, apk_cls=_APK)
    client = ApkClient()
    assert client.available is True

    apk = _apk_file(tmp_path)
    first = client._apk(apk)
    second = client._apk(apk)
    assert first is second
    assert built == [str(apk.expanduser().resolve())]


def test_apk_light_cache_evicts_oldest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _APK:
        def __init__(self, path: str) -> None:
            self.path = path

    _install_fake_androguard(monkeypatch, apk_cls=_APK)
    client = ApkClient()
    for index in range(5):
        client._apk(_apk_file(tmp_path, f"app{index}.apk"))
    assert len(ApkClient._light_cache) == 4


def test_apk_light_parse_failure_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomAPK:
        def __init__(self, path: str) -> None:
            raise RuntimeError("corrupt zip")

    _install_fake_androguard(monkeypatch, apk_cls=_BoomAPK)
    client = ApkClient()
    with pytest.raises(ApkError) as exc:
        client._apk(_apk_file(tmp_path))
    assert exc.value.code == "backend_error"


# --- _parsed full-cache plumbing --------------------------------------------


def test_parsed_full_cache_parses_once_then_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def _analyze(path: str) -> tuple[str, str, str]:
        calls.append(path)
        return ("apk-obj", "dex-obj", "analysis-obj")

    _install_fake_androguard(monkeypatch, analyze=_analyze)
    client = ApkClient()
    apk = _apk_file(tmp_path)
    first = client._parsed(apk)
    second = client._parsed(apk)
    assert first is second
    assert isinstance(first, _ParsedApk)
    assert first.apk == "apk-obj"
    assert first.analysis == "analysis-obj"
    assert first._dex == "dex-obj"
    assert len(calls) == 1


def test_parsed_full_cache_evicts_oldest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _analyze(path: str) -> tuple[str, str, str]:
        return ("apk", "dex", "analysis")

    _install_fake_androguard(monkeypatch, analyze=_analyze)
    client = ApkClient()
    for index in range(5):
        client._parsed(_apk_file(tmp_path, f"app{index}.apk"))
    assert len(ApkClient._full_cache) == 4


def test_parsed_analyze_failure_is_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _analyze(path: str) -> tuple[str, str, str]:
        raise RuntimeError("dex explosion")

    _install_fake_androguard(monkeypatch, analyze=_analyze)
    client = ApkClient()
    with pytest.raises(ApkError) as exc:
        client._parsed(_apk_file(tmp_path))
    assert exc.value.code == "backend_error"


# --- manifest / permissions / certificates error branches -------------------


def test_manifest_decode_failure_is_backend_error() -> None:
    class _Apk:
        def get_package(self) -> str:
            return "com.x"

        def get_android_manifest_axml(self) -> Any:
            raise RuntimeError("axml unreadable")

    client = ApkClient()
    client._apk = lambda _path: _Apk()  # type: ignore[method-assign]
    with pytest.raises(ApkError) as exc:
        client.manifest(Path("dummy.apk"))
    assert exc.value.code == "backend_error"


def test_permissions_falls_back_when_requested_unavailable() -> None:
    class _Apk:
        def get_permissions(self) -> list[str]:
            return ["B", "A"]

        def get_requested_permissions(self) -> list[str]:
            raise RuntimeError("older androguard")

    client = ApkClient()
    client._apk = lambda _path: _Apk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert payload["permissions"] == ["A", "B"]
    assert payload["requested_permissions"] == ["A", "B"]


def test_certificates_tolerates_signature_and_cert_failures() -> None:
    class _BadCert:
        @property
        def subject(self) -> str:
            raise ValueError("unreadable certificate")

    class _Apk:
        def get_signature_names(self) -> list[str]:
            raise RuntimeError("no signature block")

        def get_certificates(self) -> list[Any]:
            return [_BadCert()]

    client = ApkClient()
    client._apk = lambda _path: _Apk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["signature_files"] == []
    assert payload["certificates"] == []
    assert payload["v1_signed"] is False


# --- native_libs 2-part path branch -----------------------------------------


def test_native_libs_skips_abi_for_short_path() -> None:
    class _Apk:
        def get_files(self) -> list[str]:
            return ["lib/toplevel.so", "lib/arm64-v8a/libx.so", "assets/data.bin"]

    client = ApkClient()
    client._apk = lambda _path: _Apk()  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert payload["abis"] == ["arm64-v8a"]
    assert "lib/toplevel.so" in payload["native_libs"]


# --- classes / methods / xrefs guards ---------------------------------------


class _Klass:
    def __init__(self, name: str, *, external: bool = False, methods: list[Any] | None = None):
        self.name = name
        self._external = external
        self._methods = methods or []

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[Any]:
        return self._methods


class _Method:
    def __init__(self, name: str, *, external: bool = False, xrefs: list[Any] | None = None):
        self.name = name
        self._external = external
        self._xrefs = xrefs or []

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[Any]:
        return self._xrefs


class _Analysis:
    def __init__(self, classes: list[Any] | None = None, methods: list[Any] | None = None):
        self._classes = classes or []
        self._methods = methods or []

    def get_classes(self) -> list[Any]:
        return self._classes

    def get_methods(self) -> list[Any]:
        return self._methods


def _with_analysis(client: ApkClient, analysis: _Analysis) -> None:
    client._parsed = lambda _path: _ParsedApk(None, analysis, None)  # type: ignore[method-assign]


def test_classes_skips_external() -> None:
    client = ApkClient()
    _with_analysis(
        client, _Analysis(classes=[_Klass("Lext;", external=True), _Klass("Lreal;")])
    )
    payload = client.classes(Path("dummy.apk"))
    assert payload["classes"] == ["Lreal;"]


def test_methods_rejects_blank_class_name() -> None:
    client = ApkClient()
    _with_analysis(client, _Analysis(classes=[]))
    with pytest.raises(ApkError) as exc:
        client.methods(Path("dummy.apk"), "   ")
    assert exc.value.code == "invalid_params"


def test_methods_reports_missing_class() -> None:
    client = ApkClient()
    _with_analysis(client, _Analysis(classes=[_Klass("Lother;")]))
    with pytest.raises(ApkError) as exc:
        client.methods(Path("dummy.apk"), "Lnope;")
    assert exc.value.code == "not_found"


def test_xrefs_rejects_blank_method_name() -> None:
    client = ApkClient()
    _with_analysis(client, _Analysis(methods=[]))
    with pytest.raises(ApkError) as exc:
        client.xrefs(Path("dummy.apk"), "  ")
    assert exc.value.code == "invalid_params"


def test_xrefs_skips_external_and_mismatched_methods() -> None:
    client = ApkClient()
    analysis = _Analysis(
        methods=[_Method("other"), _Method("target", external=True)]
    )
    _with_analysis(client, analysis)
    payload = client.xrefs(Path("dummy.apk"), "target")
    assert payload["callers"] == []
    assert payload["has_more"] is False


# --- _dotted_to_smali already-smali passthrough -----------------------------


def test_dotted_to_smali_passthrough_and_conversion() -> None:
    assert _dotted_to_smali("Lcom/x/Foo;") == "Lcom/x/Foo;"
    assert _dotted_to_smali("com.x.Foo") == "Lcom/x/Foo;"
