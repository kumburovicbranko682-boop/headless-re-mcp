"""APK backend paths the field suites bypass by stubbing _apk / _parsed.

These exercise the process-wide parse cache (miss, hit-with-LRU-touch,
eviction, release-on-close), the availability / not-found guards every read
funnels through, and the per-operation fallback and error branches that keep a
version-skewed androguard or a non-APK zip from being reported as clean data.
The cache is a ClassVar shared across the process, so each cache test clears it
first and the fixture clears it again on the way out.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    _CACHE_LIMIT,
    ApkClient,
    ApkError,
    _dotted_to_smali,
    _ParsedApk,
)


@pytest.fixture(autouse=True)
def _clean_apk_cache() -> Any:
    def clear() -> None:
        with ApkClient._cache_lock:
            ApkClient._light_cache.clear()
            ApkClient._full_cache.clear()

    clear()
    yield
    clear()


def _apk_file(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04not-a-real-apk")
    return path


# ---------------------------------------------------------------------------
# availability and the file guard
# ---------------------------------------------------------------------------
def test_available_reports_the_installed_module() -> None:
    assert ApkClient().available is True


def test_require_reports_capability_unavailable_without_androguard() -> None:
    client = ApkClient()
    client._available = False
    with pytest.raises(ApkError) as caught:
        client._apk(Path("whatever.apk"))
    assert caught.value.code == "capability_unavailable"


def test_require_reports_not_found_for_a_missing_file(tmp_path: Path) -> None:
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._apk(tmp_path / "absent.apk")
    assert caught.value.code == "not_found"


# ---------------------------------------------------------------------------
# _apk light cache: miss, hit, eviction, parse failure
# ---------------------------------------------------------------------------
class _FakeAPK:
    instances = 0

    def __init__(self, path: str) -> None:
        type(self).instances += 1
        self.path = path
        self.serial = type(self).instances


def test_apk_caches_the_parse_and_touches_it_on_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _FakeAPK.instances = 0
    monkeypatch.setattr("androguard.core.apk.APK", _FakeAPK)
    client = ApkClient()
    target = _apk_file(tmp_path, "a.apk")
    first = client._apk(target)
    second = client._apk(target)
    # A second read is served from cache, not reparsed.
    assert first is second
    assert _FakeAPK.instances == 1


def test_apk_cache_evicts_the_oldest_over_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("androguard.core.apk.APK", _FakeAPK)
    client = ApkClient()
    files = [_apk_file(tmp_path, f"app{i}.apk") for i in range(_CACHE_LIMIT + 1)]
    for path in files:
        client._apk(path)
    with ApkClient._cache_lock:
        assert len(ApkClient._light_cache) == _CACHE_LIMIT


def test_apk_maps_a_parse_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(path: str) -> None:
        raise ValueError("bad zip")

    monkeypatch.setattr("androguard.core.apk.APK", boom)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._apk(_apk_file(tmp_path, "bad.apk"))
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# _parsed full cache
# ---------------------------------------------------------------------------
def test_parsed_caches_the_full_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def fake_analyze(path: str) -> tuple[object, object, object]:
        calls["n"] += 1
        return object(), object(), object()

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", fake_analyze)
    client = ApkClient()
    target = _apk_file(tmp_path, "full.apk")
    first = client._parsed(target)
    second = client._parsed(target)
    assert isinstance(first, _ParsedApk)
    assert first is second
    assert calls["n"] == 1


def test_parsed_cache_evicts_the_oldest_over_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "androguard.misc.AnalyzeAPK", lambda path: (object(), object(), object())
    )
    client = ApkClient()
    for i in range(_CACHE_LIMIT + 1):
        client._parsed(_apk_file(tmp_path, f"full{i}.apk"))
    with ApkClient._cache_lock:
        assert len(ApkClient._full_cache) == _CACHE_LIMIT


def test_parsed_maps_an_analysis_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(path: str) -> None:
        raise RuntimeError("dex explosion")

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", boom)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._parsed(_apk_file(tmp_path, "boom.apk"))
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------
def test_release_drops_cached_parses_for_one_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("androguard.core.apk.APK", _FakeAPK)
    monkeypatch.setattr(
        "androguard.misc.AnalyzeAPK", lambda path: (object(), object(), object())
    )
    client = ApkClient()
    target = _apk_file(tmp_path, "drop.apk")
    client._apk(target)
    client._parsed(target)
    assert ApkClient.release(target) is True
    # Nothing left to drop the second time.
    assert ApkClient.release(target) is False


def test_release_returns_false_when_the_path_cannot_be_resolved() -> None:
    class _BadPath:
        def expanduser(self) -> _BadPath:
            return self

        def resolve(self) -> Path:
            raise OSError("no such filesystem")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# per-operation fallback and error branches
# ---------------------------------------------------------------------------
class _ManifestBoom:
    def get_package(self) -> str:
        return "com.example.app"

    def get_android_manifest_axml(self) -> Any:
        raise RuntimeError("axml corrupt")


def test_manifest_maps_a_decode_failure_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _ManifestBoom())
    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "a.apk")
    assert caught.value.code == "backend_error"


class _PermFallbackApk:
    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        raise AttributeError("older androguard")


def test_permissions_falls_back_when_requested_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _PermFallbackApk())
    payload = client.permissions(tmp_path / "a.apk")
    assert payload["permissions"] == ["android.permission.INTERNET"]
    # requested mirrors declared when the newer API is missing.
    assert payload["requested_permissions"] == ["android.permission.INTERNET"]


class _BadCert:
    @property
    def subject(self) -> str:
        raise RuntimeError("certificate object shape changed")


class _CertNamesBoomApk:
    def get_signature_names(self) -> list[str]:
        raise RuntimeError("v1 block missing")

    def get_certificates(self) -> list[_BadCert]:
        return [_BadCert()]


def test_certificates_tolerates_missing_names_and_odd_cert_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _CertNamesBoomApk())
    payload = client.certificates(tmp_path / "a.apk")
    # No signature names -> not v1 signed; the unreadable cert is skipped.
    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False
    assert payload["certificates"] == []


class _NativeLibsApk:
    def get_files(self) -> list[str]:
        return [
            "lib/arm64-v8a/libfoo.so",
            "lib/onlyone",  # under lib/ but no abi segment
            "res/layout/main.xml",  # not a native lib
            "lib/x86/liba.so",
            "lib/x86/libb.so",
        ]


def test_native_libs_reports_abis_and_flags_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_NATIVE_LIBS", 1)
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _NativeLibsApk())
    payload = client.native_libs(tmp_path / "a.apk")
    assert payload["has_more"] is True
    assert "arm64-v8a" in payload["abis"]
    assert "x86" in payload["abis"]
    assert payload["count"] == 1  # capped at _MAX_NATIVE_LIBS


class _ClassObj:
    def __init__(self, name: str, external: bool) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _ClassParsed:
    def __init__(self, classes: list[_ClassObj]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_ClassObj]:
        return self._classes


def test_classes_skips_external_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _ClassParsed(
        [_ClassObj("Lcom/app/Real;", False), _ClassObj("Ljava/lang/Object;", True)]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.classes(tmp_path / "a.apk")
    assert payload["classes"] == ["Lcom/app/Real;"]
    assert payload["total"] == 1


def test_methods_requires_a_class_name_and_reports_a_missing_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _ClassParsed([_ClassObj("Lcom/app/Real;", False)])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    with pytest.raises(ApkError) as blank:
        client.methods(tmp_path / "a.apk", "   ")
    assert blank.value.code == "invalid_params"
    with pytest.raises(ApkError) as missing:
        client.methods(tmp_path / "a.apk", "com.app.Nope")
    assert missing.value.code == "not_found"


class _XrefMethod:
    def __init__(self, name: str, external: bool) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, object, int]]:
        return []


class _XrefParsed:
    def __init__(self, methods: list[_XrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_XrefMethod]:
        return self._methods


def test_xrefs_requires_a_name_and_skips_unmatched_methods(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _XrefParsed(
        [_XrefMethod("decrypt", True), _XrefMethod("other", False)]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    with pytest.raises(ApkError) as blank:
        client.xrefs(tmp_path / "a.apk", "  ")
    assert blank.value.code == "invalid_params"
    # An external match and a name mismatch both leave callers empty and final.
    payload = client.xrefs(tmp_path / "a.apk", "decrypt")
    assert payload["callers"] == []
    assert payload["has_more"] is False


def test_dotted_to_smali_passes_through_smali_and_converts_dotted() -> None:
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
