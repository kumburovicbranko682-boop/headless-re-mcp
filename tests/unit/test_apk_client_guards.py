"""Cache/require internals and per-method readers of the androguard APK backend.

The ``test_apk_*_fields.py`` suite pins the payload field names by monkeypatching
``_apk``/``_parsed``; this reaches the layer under them -- capability and
not-found gating, the light/full parse caches (hit, insert, evict, backend-error
remap), and the manifest-level and analysis readers with their caps and honesty
branches. androguard is an optional extra the quality CI omits, so the lazy
``APK``/``AnalyzeAPK`` imports are satisfied with fake modules injected into
``sys.modules`` rather than a real parse.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    _CACHE_LIMIT,
    _MAX_CERTIFICATES,
    ApkClient,
    ApkError,
    _cap_names,
    _clamp_page,
    _dotted_to_smali,
    _ParsedApk,
)


class _FakeApk:
    """A manifest-level androguard APK stand-in; every getter is overridable."""

    def __init__(self, **overrides: Any) -> None:
        self._values: dict[str, Any] = {
            "get_package": "com.example.app",
            "get_androidversion_name": "1.2.3",
            "get_androidversion_code": "45",
            "get_min_sdk_version": "21",
            "get_target_sdk_version": "33",
            "get_main_activity": "com.example.app.Main",
            "get_permissions": ["android.permission.INTERNET"],
            "get_requested_permissions": ["android.permission.INTERNET"],
            "get_activities": ["com.example.app.Main"],
            "get_services": ["com.example.app.Svc"],
            "get_receivers": [],
            "get_providers": [],
            "get_files": ["classes.dex", "lib/arm64-v8a/libfoo.so", "lib/x86/libbar.so"],
            "get_signature_names": ["META-INF/CERT.RSA"],
            "get_certificates": [],
        }
        self._values.update(overrides)

    def __getattr__(self, name: str) -> Any:
        if name in self.__dict__.get("_values", {}):
            value = self._values[name]
            if isinstance(value, Exception):
                def _raise(*_a: Any, **_k: Any) -> Any:
                    raise value

                return _raise
            return lambda *a, **k: value
        raise AttributeError(name)

    def get_android_manifest_axml(self) -> Any:
        return types.SimpleNamespace(get_xml=lambda: b"<manifest/>")


class _FakeCert:
    def __init__(self, index: int) -> None:
        self.subject = f"CN=Signer{index}"
        self.issuer = f"CN=Issuer{index}"
        self.serial_number = index
        self.sha256_fingerprint = f"{index:064x}"


class _BadCert:
    @property
    def subject(self) -> str:
        raise RuntimeError("unreadable certificate")


def _install_fake_androguard(
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk_factory: Any = None,
    analyze_factory: Any = None,
) -> None:
    for name in ("androguard", "androguard.core", "androguard.core.apk", "androguard.misc"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    core_apk = sys.modules["androguard.core.apk"]
    core_apk.APK = apk_factory or (lambda path: _FakeApk())  # type: ignore[attr-defined]
    misc = sys.modules["androguard.misc"]
    misc.AnalyzeAPK = analyze_factory or (  # type: ignore[attr-defined]
        lambda path: (_FakeApk(), object(), object())
    )


def _client() -> ApkClient:
    client = ApkClient()
    client._available = True
    return client


def _apk_file(tmp_path: Path) -> Path:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04and-more")
    return apk


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------
def test_cap_names_sorts_and_flags_overflow() -> None:
    names, more = _cap_names(["b", "a", "c"], 2)
    assert more is True
    assert names == sorted(names)
    assert len(names) == 2
    assert _cap_names(None, 5) == ([], False)


def test_clamp_page_floors_negatives_and_caps_the_limit() -> None:
    assert _clamp_page(-5, 10, max_limit=100) == (0, 10)
    assert _clamp_page(3, -1, max_limit=100) == (3, 1)
    assert _clamp_page(3, 999, max_limit=100) == (3, 100)


def test_dotted_to_smali_converts_and_passes_through() -> None:
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"


def test_parsed_apk_holds_its_three_handles() -> None:
    parsed = _ParsedApk("apk", "analysis", "dex")
    assert parsed.apk == "apk"
    assert parsed.analysis == "analysis"
    assert parsed._dex == "dex"


# ---------------------------------------------------------------------------
# capability / require / cache
# ---------------------------------------------------------------------------
def test_require_gates_on_capability_then_existence(tmp_path: Path) -> None:
    absent = ApkClient()
    absent._available = False
    with pytest.raises(ApkError) as unavailable:
        absent._require(tmp_path / "x.apk")
    assert unavailable.value.code == "capability_unavailable"

    client = _client()
    with pytest.raises(ApkError) as missing:
        client._require(tmp_path / "gone.apk")
    assert missing.value.code == "not_found"

    apk = _apk_file(tmp_path)
    assert client._require(apk) == apk.resolve()


def test_available_property_reflects_import() -> None:
    # Without the extra installed the real import fails, so a fresh client is
    # unavailable; the flag simply mirrors that.
    assert ApkClient().available in (True, False)


def test_apk_parses_caches_and_remaps_backend_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ApkClient._light_cache.clear()
    calls: list[str] = []

    def factory(path: str) -> _FakeApk:
        calls.append(path)
        return _FakeApk()

    _install_fake_androguard(monkeypatch, apk_factory=factory)
    client = _client()
    apk = _apk_file(tmp_path)
    first = client._apk(apk)
    second = client._apk(apk)
    assert first is second  # second call served from the light cache
    assert len(calls) == 1

    def boom(path: str) -> _FakeApk:
        raise ValueError("bad zip")

    _install_fake_androguard(monkeypatch, apk_factory=boom)
    ApkClient._light_cache.clear()
    with pytest.raises(ApkError) as caught:
        client._apk(apk)
    assert caught.value.code == "backend_error"


def test_apk_cache_evicts_the_oldest_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ApkClient._light_cache.clear()
    _install_fake_androguard(monkeypatch)
    client = _client()
    files = []
    for index in range(_CACHE_LIMIT + 2):
        apk = tmp_path / f"app{index}.apk"
        apk.write_bytes(b"PK" + bytes([index]))
        files.append(apk)
        client._apk(apk)
    assert len(ApkClient._light_cache) == _CACHE_LIMIT


def test_parsed_analyzes_and_remaps_backend_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ApkClient._full_cache.clear()

    def boom(path: str) -> Any:
        raise RuntimeError("dex analysis failed")

    _install_fake_androguard(monkeypatch, analyze_factory=boom)
    client = _client()
    with pytest.raises(ApkError) as caught:
        client._parsed(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"


def test_parsed_caches_the_full_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ApkClient._full_cache.clear()
    calls: list[str] = []

    def analyze(path: str) -> Any:
        calls.append(path)
        return _FakeApk(), object(), object()

    _install_fake_androguard(monkeypatch, analyze_factory=analyze)
    client = _client()
    apk = _apk_file(tmp_path)
    first = client._parsed(apk)
    second = client._parsed(apk)
    assert first is second  # served from the full cache
    assert len(calls) == 1


def test_release_drops_cached_parses_and_survives_a_bad_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _apk_file(tmp_path)
    key = (str(apk.resolve()), 1)
    ApkClient._full_cache[key] = _ParsedApk("a", "b", "c")
    assert ApkClient.release(apk) is True
    assert key not in ApkClient._full_cache

    def raise_os(self: Path) -> Path:
        raise OSError("no such device")

    monkeypatch.setattr(Path, "resolve", raise_os)
    assert ApkClient.release(tmp_path / "whatever.apk") is False


# ---------------------------------------------------------------------------
# manifest-level readers
# ---------------------------------------------------------------------------
def test_open_reports_manifest_facts_and_native_abis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = _client().open(_apk_file(tmp_path))
    assert payload["opened"] is True
    assert payload["package"] == "com.example.app"
    assert payload["permission_count"] == 1
    assert payload["native_abis"] == ["arm64-v8a", "x86"]


def test_manifest_maps_a_decode_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BadManifest(_FakeApk):
        def get_android_manifest_axml(self) -> Any:
            raise RuntimeError("axml corrupt")

    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _BadManifest())
    with pytest.raises(ApkError) as caught:
        _client().manifest(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"


def test_permissions_falls_back_when_requested_is_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _FakeApk(
        get_permissions=["android.permission.INTERNET", "android.permission.CAMERA"],
        get_requested_permissions=RuntimeError("older androguard"),
    )
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    payload = _client().permissions(_apk_file(tmp_path))
    assert payload["count"] == 2
    # The fallback mirrors declared into requested rather than dropping the key.
    assert payload["requested_permissions"] == payload["permissions"]


def test_certificates_caps_files_and_certs_and_skips_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    names = [f"META-INF/CERT{i}.RSA" for i in range(_MAX_CERTIFICATES + 5)]
    certs = [_FakeCert(i) for i in range(_MAX_CERTIFICATES + 3)] + [_BadCert()]
    apk = _FakeApk(get_signature_names=names, get_certificates=certs)
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    payload = _client().certificates(_apk_file(tmp_path))
    assert len(payload["signature_files"]) == _MAX_CERTIFICATES
    assert len(payload["certificates"]) == _MAX_CERTIFICATES
    assert payload["v1_signed"] is True
    assert payload["has_more"] is True


def test_certificates_skips_an_unreadable_certificate_within_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _FakeApk(
        get_signature_names=["META-INF/CERT.RSA"],
        get_certificates=[_FakeCert(0), _BadCert(), _FakeCert(1)],
    )
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    payload = _client().certificates(_apk_file(tmp_path))
    # The unreadable middle certificate is dropped, the readable pair kept.
    assert len(payload["certificates"]) == 2


def test_certificates_tolerates_missing_signature_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _FakeApk(get_signature_names=RuntimeError("no v1 block"), get_certificates=[])
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    payload = _client().certificates(_apk_file(tmp_path))
    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False


def test_components_lists_each_category(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = _client().components(_apk_file(tmp_path))
    assert payload["activities"] == ["com.example.app.Main"]
    assert payload["services"] == ["com.example.app.Svc"]
    assert payload["main_activity"] == "com.example.app.Main"


def test_native_libs_lists_libraries_and_abis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _FakeApk(
        get_files=[
            "classes.dex",
            "lib/arm64-v8a/libfoo.so",
            "lib/x86/libbar.so",
            "lib/stray.so",  # under lib/ but with no abi segment: kept, abi skipped
        ]
    )
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    payload = _client().native_libs(_apk_file(tmp_path))
    assert "lib/arm64-v8a/libfoo.so" in payload["native_libs"]
    assert "lib/stray.so" in payload["native_libs"]
    assert payload["abis"] == ["arm64-v8a", "x86"]


# ---------------------------------------------------------------------------
# analysis readers
# ---------------------------------------------------------------------------
class _FakeKlass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[Any]:
        return [types.SimpleNamespace(name="m", descriptor="()V", access="public")]


class _FakeAnalysis:
    def __init__(self, classes: list[_FakeKlass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeKlass]:
        return self._classes

    def get_strings(self) -> list[Any]:
        return [types.SimpleNamespace(get_value=lambda: "hello")]

    def get_methods(self) -> list[Any]:
        return []


def test_classes_skips_external_and_sorts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeAnalysis(
        [_FakeKlass("Lb;"), _FakeKlass("La;"), _FakeKlass("Lext;", external=True)]
    )
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = _client().classes(_apk_file(tmp_path))
    assert payload["classes"] == ["La;", "Lb;"]
    assert payload["total"] == 2


def test_methods_requires_a_class_name_and_reports_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeAnalysis([_FakeKlass("Lcom/example/Foo;")])
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    client = _client()
    with pytest.raises(ApkError) as empty:
        client.methods(_apk_file(tmp_path), "   ")
    assert empty.value.code == "invalid_params"
    with pytest.raises(ApkError) as absent:
        client.methods(_apk_file(tmp_path), "com.example.Missing")
    assert absent.value.code == "not_found"


def test_methods_resolves_a_dotted_class_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeAnalysis([_FakeKlass("Lcom/example/Foo;")])
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = _client().methods(_apk_file(tmp_path), "com.example.Foo")
    assert payload["class_name"] == "Lcom/example/Foo;"
    assert payload["count"] == 1


def test_strings_dedupes_and_sorts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeAnalysis([]))
    payload = _client().strings(_apk_file(tmp_path))
    assert payload["strings"] == ["hello"]
    assert payload["total"] == 1


def test_xrefs_requires_a_method_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeAnalysis([]))
    with pytest.raises(ApkError) as caught:
        _client().xrefs(_apk_file(tmp_path), "  ")
    assert caught.value.code == "invalid_params"


class _XrefMethod:
    def __init__(self, name: str, *, external: bool, callers: int) -> None:
        self.name = name
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, Any, int]]:
        call = types.SimpleNamespace(class_name="Lcom/example/Caller;", name="invoke")
        return [(None, call, i) for i in range(self._callers)]


class _XrefAnalysis:
    def __init__(self, methods: list[_XrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_XrefMethod]:
        return self._methods


def test_xrefs_skips_external_and_mismatched_then_collects_callers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analysis = _XrefAnalysis(
        [
            _XrefMethod("decrypt", external=True, callers=9),  # external: skipped
            _XrefMethod("other", external=False, callers=9),  # name mismatch: skipped
            _XrefMethod("decrypt", external=False, callers=3),  # the real target
        ]
    )
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: analysis)
    payload = _client().xrefs(_apk_file(tmp_path), "decrypt", limit=10)
    assert payload["count"] == 3
    assert payload["has_more"] is False
    assert payload["callers"][0]["class"] == "Lcom/example/Caller;"
