"""Cache, require, and per-method fallback paths for the APK backend.

``test_apk_fields.py`` and friends monkeypatch ``_apk`` / ``_parsed`` and assert
the payload field contracts. This file instead exercises the layers underneath
those seams: the androguard-availability gate, the file-existence check, the
mtime-keyed light/full caches (hit, miss, eviction, release), the parse-failure
conversions, and the per-method ``except`` fallbacks that keep one flaky
androguard call from sinking a whole read. A fake ``androguard`` package stands
in for the real optional dependency so the caching layer runs without it.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_mod
from headless_re_mcp.backends.apk.client import (
    _CACHE_LIMIT,
    ApkClient,
    ApkError,
    _dotted_to_smali,
    _ParsedApk,
)


@pytest.fixture(autouse=True)
def _clear_apk_caches() -> Any:
    """The caches are process-wide ClassVars; keep tests independent."""
    with ApkClient._cache_lock:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()
    yield
    with ApkClient._cache_lock:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()


def _write_apk(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04 fake apk")
    return path


def _install_fake_androguard(
    monkeypatch: Any,
    *,
    apk_ctor: Any = None,
    analyze: Any = None,
) -> dict[str, int]:
    """Put a minimal androguard package tree on sys.modules.

    Returns a mutable counter dict so a test can assert the parse only ran once
    across two cache-hit calls.
    """
    calls = {"apk": 0, "analyze": 0}

    root = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    apk_pkg = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")

    def _default_apk(path: str) -> Any:
        return types.SimpleNamespace(path=path)

    def _APK(path: str) -> Any:
        calls["apk"] += 1
        return (apk_ctor or _default_apk)(path)

    def _AnalyzeAPK(path: str) -> Any:
        calls["analyze"] += 1
        if analyze is not None:
            return analyze(path)
        return (object(), object(), object())

    apk_pkg.APK = _APK  # type: ignore[attr-defined]
    misc.AnalyzeAPK = _AnalyzeAPK  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", root)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.apk", apk_pkg)
    monkeypatch.setitem(sys.modules, "androguard.misc", misc)
    return calls


# ---------------------------------------------------------------------------
# constructor / availability / _ParsedApk
# ---------------------------------------------------------------------------


def test_constructor_reports_available_when_androguard_imports(monkeypatch: Any) -> None:
    _install_fake_androguard(monkeypatch)
    client = ApkClient()
    assert client.available is True
    assert client._androguard is sys.modules["androguard"]


def test_parsed_apk_holds_the_three_androguard_objects() -> None:
    apk, analysis, dex = object(), object(), object()
    parsed = _ParsedApk(apk, analysis, dex)
    assert parsed.apk is apk
    assert parsed.analysis is analysis
    assert parsed._dex is dex


# ---------------------------------------------------------------------------
# _require gate
# ---------------------------------------------------------------------------


def test_require_refuses_when_androguard_is_missing(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = False
    with pytest.raises(ApkError) as caught:
        client._require(_write_apk(tmp_path / "a.apk"))
    assert caught.value.code == "capability_unavailable"


def test_require_reports_a_missing_file_as_not_found(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as caught:
        client._require(tmp_path / "missing.apk")
    assert caught.value.code == "not_found"


def test_require_returns_the_resolved_path_for_a_real_file(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    apk = _write_apk(tmp_path / "a.apk")
    assert client._require(apk) == apk.resolve()


# ---------------------------------------------------------------------------
# _apk light cache: miss, hit, parse error, eviction
# ---------------------------------------------------------------------------


def test_apk_light_cache_parses_once_then_serves_from_cache(
    tmp_path: Path, monkeypatch: Any
) -> None:
    calls = _install_fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    apk_path = _write_apk(tmp_path / "a.apk")
    first = client._apk(apk_path)
    second = client._apk(apk_path)
    assert first is second
    assert calls["apk"] == 1


def test_apk_light_cache_wraps_a_parse_failure_as_backend_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    def _boom(path: str) -> Any:
        raise ValueError("bad zip central directory")

    _install_fake_androguard(monkeypatch, apk_ctor=_boom)
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as caught:
        client._apk(_write_apk(tmp_path / "a.apk"))
    assert caught.value.code == "backend_error"
    assert "failed to parse APK" in caught.value.message


def test_apk_light_cache_evicts_beyond_the_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _install_fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    for index in range(_CACHE_LIMIT + 2):
        client._apk(_write_apk(tmp_path / f"a{index}.apk"))
    with ApkClient._cache_lock:
        assert len(ApkClient._light_cache) == _CACHE_LIMIT


# ---------------------------------------------------------------------------
# _parsed full cache: miss, hit, analyze error
# ---------------------------------------------------------------------------


def test_parsed_full_cache_analyzes_once_then_serves_from_cache(
    tmp_path: Path, monkeypatch: Any
) -> None:
    calls = _install_fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    apk_path = _write_apk(tmp_path / "a.apk")
    first = client._parsed(apk_path)
    second = client._parsed(apk_path)
    assert first is second
    assert isinstance(first, _ParsedApk)
    assert calls["analyze"] == 1


def test_parsed_full_cache_wraps_an_analyze_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    def _boom(path: str) -> Any:
        raise RuntimeError("dex parse overflow")

    _install_fake_androguard(monkeypatch, analyze=_boom)
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as caught:
        client._parsed(_write_apk(tmp_path / "a.apk"))
    assert caught.value.code == "backend_error"
    assert "failed to analyze APK" in caught.value.message


def test_parsed_full_cache_evicts_beyond_the_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _install_fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    for index in range(_CACHE_LIMIT + 2):
        client._parsed(_write_apk(tmp_path / f"a{index}.apk"))
    with ApkClient._cache_lock:
        assert len(ApkClient._full_cache) == _CACHE_LIMIT


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------


def test_release_drops_cached_parses_for_one_path(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _install_fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    apk_path = _write_apk(tmp_path / "a.apk")
    client._apk(apk_path)
    client._parsed(apk_path)
    with ApkClient._cache_lock:
        assert ApkClient._light_cache and ApkClient._full_cache
    assert ApkClient.release(apk_path) is True
    with ApkClient._cache_lock:
        assert not ApkClient._light_cache
        assert not ApkClient._full_cache
    # A second release finds nothing left to drop.
    assert ApkClient.release(apk_path) is False


def test_release_returns_false_when_the_path_cannot_be_resolved() -> None:
    class _BadPath:
        def expanduser(self) -> Any:
            raise OSError("cannot resolve")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# open native_abis + per-method fallbacks
# ---------------------------------------------------------------------------


class _OpenApk:
    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "34"

    def get_main_activity(self) -> str:
        return "com.example.Main"

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_files(self) -> list[str]:
        return [
            "lib/arm64-v8a/libnative.so",
            "lib/armeabi-v7a/libnative.so",
            "lib",  # too short: skipped by the len>=3 guard
            "res/x.png",
        ]


def test_open_collects_native_abis_from_lib_entries(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _OpenApk())
    payload = client.open(tmp_path / "a.apk")
    assert payload["opened"] is True
    assert payload["package"] == "com.example.app"
    assert payload["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert payload["permission_count"] == 1


def test_manifest_wraps_a_decode_failure(tmp_path: Path, monkeypatch: Any) -> None:
    class _Apk:
        def get_android_manifest_axml(self) -> Any:
            raise RuntimeError("axml corrupt")

        def get_package(self) -> str:
            return "com.example.app"

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "a.apk")
    assert caught.value.code == "backend_error"


def test_permissions_falls_back_to_declared_when_requested_is_unavailable(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Apk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET", "android.permission.CAMERA"]

        def get_requested_permissions(self) -> Any:
            raise AttributeError("older androguard")

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = client.permissions(tmp_path / "a.apk")
    assert payload["permissions"] == payload["requested_permissions"]
    assert payload["count"] == 2


def test_certificates_tolerates_missing_signature_names_and_bad_certs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _BadCert:
        # Reading any attribute blows up: the per-cert guard must skip it, not
        # sink the whole listing.
        @property
        def subject(self) -> str:
            raise RuntimeError("cert object broken")

    class _Apk:
        def get_signature_names(self) -> Any:
            raise RuntimeError("no v1 block")

        def get_certificates(self) -> list[Any]:
            return [_BadCert()]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = client.certificates(tmp_path / "a.apk")
    assert payload["signature_files"] == []
    assert payload["certificates"] == []
    assert payload["v1_signed"] is False


def test_native_libs_lists_libs_and_derives_abis(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Apk:
        def get_files(self) -> list[str]:
            return [
                "lib/arm64-v8a/libfoo.so",
                "lib/onlyone",  # len(parts) < 3: contributes no abi
                "res/x.png",  # not under lib/: skipped entirely
            ]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = client.native_libs(tmp_path / "a.apk")
    assert payload["native_libs"] == ["lib/arm64-v8a/libfoo.so", "lib/onlyone"]
    assert payload["abis"] == ["arm64-v8a"]
    assert payload["has_more"] is False


def test_classes_reports_scan_capped_when_collection_stops_early(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Class:
        def __init__(self, name: str) -> None:
            self.name = name

        def is_external(self) -> bool:
            return False

    class _Parsed:
        analysis: Any

        def __init__(self) -> None:
            self.analysis = self

        def get_classes(self) -> list[Any]:
            return [_Class("La;"), _Class("Lb;"), _Class("Lc;")]

    monkeypatch.setattr(apk_mod, "_MAX_CLASSES_COLLECT", 1)
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    payload = client.classes(tmp_path / "a.apk")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_methods_reports_scan_capped_when_collection_stops_early(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Method:
        def __init__(self, index: int) -> None:
            self.name = f"m{index}"
            self.descriptor = "()V"
            self.access = "public"

    class _Class:
        name = "Lcom/example/Foo;"

        def get_methods(self) -> list[Any]:
            return [_Method(index) for index in range(3)]

    monkeypatch.setattr(apk_mod, "_MAX_METHODS_COLLECT", 1)
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _MethodsParsed([_Class()])
    )
    payload = client.methods(tmp_path / "a.apk", "com.example.Foo")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_strings_reports_scan_capped_when_collection_stops_early(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Str:
        def __init__(self, value: str) -> None:
            self._value = value

        def get_value(self) -> str:
            return self._value

    class _Parsed:
        analysis: Any

        def __init__(self) -> None:
            self.analysis = self

        def get_strings(self) -> list[Any]:
            return [_Str("alpha"), _Str("beta"), _Str("gamma")]

    monkeypatch.setattr(apk_mod, "_MAX_STRINGS_COLLECT", 1)
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    payload = client.strings(tmp_path / "a.apk")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_classes_skips_external_classes(tmp_path: Path, monkeypatch: Any) -> None:
    class _Class:
        def __init__(self, name: str, external: bool) -> None:
            self.name = name
            self._external = external

        def is_external(self) -> bool:
            return self._external

    class _Parsed:
        analysis: Any

        def __init__(self) -> None:
            self.analysis = self

        def get_classes(self) -> list[Any]:
            return [_Class("Lreal;", False), _Class("Lext;", True)]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    payload = client.classes(tmp_path / "a.apk")
    assert payload["classes"] == ["Lreal;"]
    assert payload["total"] == 1


class _MethodsParsed:
    def __init__(self, classes: list[Any]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[Any]:
        return self._classes


def test_methods_requires_a_class_name(tmp_path: Path, monkeypatch: Any) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _MethodsParsed([]))
    with pytest.raises(ApkError) as caught:
        client.methods(tmp_path / "a.apk", "   ")
    assert caught.value.code == "invalid_params"


def test_methods_reports_an_unknown_class_as_not_found(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Class:
        name = "Lcom/example/Other;"

    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _MethodsParsed([_Class()])
    )
    with pytest.raises(ApkError) as caught:
        client.methods(tmp_path / "a.apk", "com.example.Missing")
    assert caught.value.code == "not_found"


def test_methods_resolves_a_dotted_class_via_smali_form(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Method:
        name = "decrypt"
        descriptor = "()V"
        access = "public"

    class _Class:
        name = "Lcom/example/Foo;"

        def get_methods(self) -> list[Any]:
            return [_Method()]

    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _MethodsParsed([_Class()])
    )
    payload = client.methods(tmp_path / "a.apk", "com.example.Foo")
    assert payload["class_name"] == "Lcom/example/Foo;"
    assert payload["methods"][0]["name"] == "decrypt"


def test_xrefs_requires_a_method_name(tmp_path: Path, monkeypatch: Any) -> None:
    class _Parsed:
        analysis: Any

        def __init__(self) -> None:
            self.analysis = self

        def get_methods(self) -> list[Any]:
            return []

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    with pytest.raises(ApkError) as caught:
        client.xrefs(tmp_path / "a.apk", "  ")
    assert caught.value.code == "invalid_params"


def test_xrefs_skips_external_and_mismatched_methods(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Call:
        class_name = "Lcom/example/Caller;"
        name = "invoke"

    class _Method:
        def __init__(self, name: str, external: bool, callers: int) -> None:
            self.name = name
            self._external = external
            self._callers = callers

        def is_external(self) -> bool:
            return self._external

        def get_xref_from(self) -> list[Any]:
            return [(None, _Call(), 0) for _ in range(self._callers)]

    class _Parsed:
        analysis: Any

        def __init__(self) -> None:
            self.analysis = self

        def get_methods(self) -> list[Any]:
            return [
                _Method("decrypt", True, 3),  # external: skipped
                _Method("other", False, 3),  # name mismatch: skipped
                _Method("decrypt", False, 2),  # the real match
            ]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    payload = client.xrefs(tmp_path / "a.apk", "decrypt")
    assert payload["count"] == 2
    assert payload["has_more"] is False


# ---------------------------------------------------------------------------
# _dotted_to_smali
# ---------------------------------------------------------------------------


def test_dotted_to_smali_maps_dotted_names_and_passes_smali_through() -> None:
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
    # Already-smali input is returned unchanged rather than double-wrapped.
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"


def test_module_error_is_a_runtime_error() -> None:
    assert issubclass(apk_mod.ApkError, RuntimeError)
