"""ApkClient must cache safely, map androguard failures, and bound its getters.

The field/description suites drive the happy getters with a faked ``_apk`` /
``_parsed``. This module exercises the machinery underneath and the defensive
arms the getters keep for a hostile or version-skewed APK:

* the optional-dependency gate (``__init__`` import failure, ``_require``
  capability/not-found), and ``release`` dropping or shrugging off a path,
* ``_apk`` / ``_parsed`` caching, LRU reuse, and the ``backend_error`` they
  raise when androguard cannot parse or analyze the file,
* the per-getter guards: certificates tolerating a missing signature list and
  a version-skewed certificate object, ``native_libs`` skipping a short path,
  ``classes`` skipping externals, ``methods`` reporting an unknown class, and
  ``xrefs`` skipping unrelated methods.

androguard is installed here, but the ``APK`` / ``AnalyzeAPK`` entry points are
monkeypatched so no real APK is parsed.
"""

from __future__ import annotations

import builtins
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _dotted_to_smali,
    _ParsedApk,
)


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    """The parse caches are class-level; keep them from leaking between tests."""
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _apk_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.apk"
    path.write_bytes(b"PK\x03\x04 not really a zip")
    return path


# --------------------------------------------------------------------------
# optional-dependency gate + release
# --------------------------------------------------------------------------


def test_missing_androguard_degrades_to_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def deny(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "androguard" or name.startswith("androguard."):
            raise ImportError("no androguard")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny)
    client = ApkClient()
    assert client.available is False


def test_require_refuses_when_androguard_is_absent(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = False
    with pytest.raises(ApkError) as exc:
        client._require(_apk_file(tmp_path))
    assert exc.value.code == "capability_unavailable"


def test_require_reports_a_missing_file(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as exc:
        client._require(tmp_path / "absent.apk")
    assert exc.value.code == "not_found"


def test_release_drops_cached_entries_for_a_path(tmp_path: Path) -> None:
    path = _apk_file(tmp_path)
    resolved = str(path.expanduser().resolve())
    ApkClient._light_cache[(resolved, 1)] = object()
    ApkClient._full_cache[(resolved, 1)] = _ParsedApk(object(), object(), object())
    assert ApkClient.release(path) is True
    assert all(key[0] != resolved for key in ApkClient._light_cache)
    assert all(key[0] != resolved for key in ApkClient._full_cache)


def test_release_is_false_when_nothing_is_cached(tmp_path: Path) -> None:
    assert ApkClient.release(_apk_file(tmp_path)) is False


def test_release_shrugs_off_an_unresolvable_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(self: Path, *args: Any, **kwargs: Any) -> Path:
        raise OSError("cannot resolve")

    monkeypatch.setattr(Path, "resolve", boom)
    assert ApkClient.release(Path("whatever.apk")) is False


# --------------------------------------------------------------------------
# _apk / _parsed caching and parse-error mapping
# --------------------------------------------------------------------------


def test_apk_parses_once_and_then_serves_from_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _apk_file(tmp_path)
    constructions: list[str] = []

    class _FakeAPK:
        def __init__(self, target: str) -> None:
            constructions.append(target)

    monkeypatch.setattr("androguard.core.apk.APK", _FakeAPK)
    client = ApkClient()
    client._available = True
    first = client._apk(path)
    second = client._apk(path)
    assert first is second
    assert len(constructions) == 1


def test_apk_maps_a_parse_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(target: str) -> Any:
        raise ValueError("bad zip central directory")

    monkeypatch.setattr("androguard.core.apk.APK", explode)
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as exc:
        client._apk(_apk_file(tmp_path))
    assert exc.value.code == "backend_error"
    assert "failed to parse" in str(exc.value)


def test_parsed_analyzes_once_and_then_serves_from_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _apk_file(tmp_path)
    analyses: list[str] = []

    def fake_analyze(target: str) -> tuple[object, object, object]:
        analyses.append(target)
        return object(), object(), object()

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", fake_analyze)
    client = ApkClient()
    client._available = True
    first = client._parsed(path)
    second = client._parsed(path)
    assert first is second
    assert isinstance(first, _ParsedApk)
    assert len(analyses) == 1


def test_parsed_maps_an_analysis_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(target: str) -> Any:
        raise RuntimeError("dex is truncated")

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", explode)
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as exc:
        client._parsed(_apk_file(tmp_path))
    assert exc.value.code == "backend_error"
    assert "failed to analyze" in str(exc.value)


# --------------------------------------------------------------------------
# getter defensive branches
# --------------------------------------------------------------------------


class _Cert:
    def __init__(self, *, raising: bool = False) -> None:
        self._raising = raising

    @property
    def subject(self) -> str:
        if self._raising:
            raise ValueError("version-skewed certificate object")
        return "CN=x"

    @property
    def issuer(self) -> str:
        return "CN=ca"

    @property
    def serial_number(self) -> int:
        return 7

    @property
    def sha256_fingerprint(self) -> str:
        return "ab"


class _CertApk:
    def __init__(self, *, names_raise: bool, certs: list[_Cert]) -> None:
        self._names_raise = names_raise
        self._certs = certs

    def get_signature_names(self) -> list[str]:
        if self._names_raise:
            raise RuntimeError("older androguard has no signature list")
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[_Cert]:
        return self._certs


def test_certificates_tolerates_missing_names_and_skewed_certs(
    tmp_path: Path,
) -> None:
    client = ApkClient()
    client._available = True
    apk = _CertApk(names_raise=True, certs=[_Cert(raising=True), _Cert()])
    client._apk = lambda _path: apk  # type: ignore[assignment]
    payload = client.certificates(_apk_file(tmp_path))
    # The raising signature list degrades to empty; the skewed cert is skipped
    # and only the clean one survives.
    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False
    assert len(payload["certificates"]) == 1


class _LibApk:
    def __init__(self, files: list[str]) -> None:
        self._files = files

    def get_files(self) -> list[str]:
        return self._files


def test_native_libs_skips_a_path_without_an_abi_segment(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    apk = _LibApk(["lib/short.so", "lib/arm64-v8a/libx.so", "res/x.png"])
    client._apk = lambda _path: apk  # type: ignore[assignment]
    payload = client.native_libs(_apk_file(tmp_path))
    # "lib/short.so" has no ABI segment, so it contributes a lib but no abi.
    assert payload["abis"] == ["arm64-v8a"]
    assert "lib/short.so" in payload["native_libs"]


class _Klass:
    def __init__(
        self, name: str, *, external: bool = False, methods: list[Any] | None = None
    ) -> None:
        self.name = name
        self._external = external
        self._methods = methods or []

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[Any]:
        return self._methods


class _ClassAnalysis:
    def __init__(self, classes: list[_Klass]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_Klass]:
        return self._classes


def _parsed_with(analysis: Any) -> _ParsedApk:
    return _ParsedApk(object(), analysis, object())


def test_classes_skips_external_classes(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    analysis = _ClassAnalysis([_Klass("Lext;", external=True), _Klass("Lown;")])
    client._parsed = lambda _path: _parsed_with(analysis)  # type: ignore[assignment]
    payload = client.classes(_apk_file(tmp_path))
    assert payload["classes"] == ["Lown;"]
    assert payload["total"] == 1


def test_methods_reports_an_unknown_class(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    analysis = _ClassAnalysis([_Klass("Lother;")])
    client._parsed = lambda _path: _parsed_with(analysis)  # type: ignore[assignment]
    with pytest.raises(ApkError) as exc:
        client.methods(_apk_file(tmp_path), "com.x.Missing")
    assert exc.value.code == "not_found"


class _Method:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[Any]:
        return []


class _MethodAnalysis:
    def __init__(self, methods: list[_Method]) -> None:
        self._methods = methods

    def get_methods(self) -> list[_Method]:
        return self._methods


def test_xrefs_skips_external_and_unrelated_methods(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    analysis = _MethodAnalysis([_Method("onCreate", external=True), _Method("other")])
    client._parsed = lambda _path: _parsed_with(analysis)  # type: ignore[assignment]
    payload = client.xrefs(_apk_file(tmp_path), "onCreate")
    assert payload["callers"] == []
    assert payload["has_more"] is False


def test_methods_requires_a_class_name(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    client._parsed = lambda _path: _parsed_with(_ClassAnalysis([]))  # type: ignore[assignment]
    with pytest.raises(ApkError) as exc:
        client.methods(_apk_file(tmp_path), "   ")
    assert exc.value.code == "invalid_params"


def test_xrefs_requires_a_method_name(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    client._parsed = lambda _path: _parsed_with(_MethodAnalysis([]))  # type: ignore[assignment]
    with pytest.raises(ApkError) as exc:
        client.xrefs(_apk_file(tmp_path), "")
    assert exc.value.code == "invalid_params"


def test_dotted_to_smali_passes_through_an_existing_descriptor() -> None:
    assert _dotted_to_smali("Lcom/x/Foo;") == "Lcom/x/Foo;"
    assert _dotted_to_smali("com.x.Foo") == "Lcom/x/Foo;"
