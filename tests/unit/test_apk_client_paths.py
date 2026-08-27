"""Branch coverage for the androguard-backed APK client.

androguard is an optional dependency and is absent on CI, so the default
constructor reports the backend unavailable. To exercise the parse/cache
internals a minimal fake ``androguard`` package tree is installed into
sys.modules; the higher-level list/query methods are driven with fake apk and
analysis objects (the same style test_apk_fields.py already uses).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_mod
from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _cap_names,
    _dotted_to_smali,
    _ParsedApk,
)


@pytest.fixture(autouse=True)
def _clear_caches() -> Any:
    # The parse caches are class-level and shared across instances, so scrub
    # them either side of every test to keep runs independent.
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _install_androguard(
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk: Any = None,
    analyze: Any = None,
) -> None:
    ag = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    core_apk = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    if apk is not None:
        core_apk.APK = apk  # type: ignore[attr-defined]
    if analyze is not None:
        misc.AnalyzeAPK = analyze  # type: ignore[attr-defined]
    for name, module in (
        ("androguard", ag),
        ("androguard.core", core),
        ("androguard.core.apk", core_apk),
        ("androguard.misc", misc),
    ):
        monkeypatch.setitem(sys.modules, name, module)


def _apk_file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04")
    return path


# ---------------------------------------------------------------------------
# tiny helpers
# ---------------------------------------------------------------------------


def test_parsed_apk_holder_keeps_its_three_parts() -> None:
    holder = _ParsedApk("APK", "ANALYSIS", "DEX")
    assert holder.apk == "APK"
    assert holder.analysis == "ANALYSIS"
    assert holder._dex == "DEX"


def test_dotted_to_smali_passes_through_existing_smali() -> None:
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"


def test_cap_names_sorts_and_flags_when_truncated() -> None:
    # The cap is applied in input order (first two: "c", "a") and only then
    # sorted, so the flagged truncation drops "b".
    names, more = _cap_names(["c", "a", "b"], 2)
    assert names == ["a", "c"]
    assert more is True
    kept, more_none = _cap_names(None, 5)
    assert kept == []
    assert more_none is False


# ---------------------------------------------------------------------------
# availability + release
# ---------------------------------------------------------------------------


def test_available_true_when_androguard_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_androguard(monkeypatch)
    client = ApkClient()
    assert client.available is True


def test_capability_unavailable_when_androguard_absent(tmp_path: Path) -> None:
    client = ApkClient()  # CI has no androguard
    assert client.available is False
    with pytest.raises(ApkError) as caught:
        client.open(_apk_file(tmp_path))
    assert caught.value.code == "capability_unavailable"


def test_release_drops_only_the_matching_path() -> None:
    ApkClient._light_cache[("/tmp/a.apk", 1)] = object()
    ApkClient._full_cache[("/tmp/a.apk", 1)] = _ParsedApk("a", "a", "a")
    ApkClient._light_cache[("/tmp/b.apk", 1)] = object()

    assert ApkClient.release(Path("/tmp/a.apk")) is True
    assert ("/tmp/a.apk", 1) not in ApkClient._light_cache
    assert ("/tmp/a.apk", 1) not in ApkClient._full_cache
    assert ("/tmp/b.apk", 1) in ApkClient._light_cache

    # nothing left for this path -> False
    assert ApkClient.release(Path("/tmp/a.apk")) is False


def test_release_returns_false_when_resolve_raises() -> None:
    class _BadPath:
        def expanduser(self) -> _BadPath:
            return self

        def resolve(self) -> Path:
            raise OSError("unresolvable")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _apk (light parse) caching, eviction, errors
# ---------------------------------------------------------------------------


def test_light_parse_caches_hits_and_evicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[str] = []

    def fake_apk(path: str) -> Any:
        built.append(path)
        return types.SimpleNamespace(source=path)

    _install_androguard(monkeypatch, apk=fake_apk)
    monkeypatch.setattr(apk_mod, "_CACHE_LIMIT", 1)
    client = ApkClient()

    first = _apk_file(tmp_path, "one.apk")
    second = _apk_file(tmp_path, "two.apk")

    obj1 = client._apk(first)
    # A repeat hit returns the same object without reparsing.
    assert client._apk(first) is obj1
    assert built == [str(first.resolve())]

    # A different apk evicts the first under the limit of one.
    obj2 = client._apk(second)
    assert obj2 is not obj1
    assert len(ApkClient._light_cache) == 1


def test_light_parse_missing_file_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch, apk=lambda path: object())
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._apk(tmp_path / "nope.apk")
    assert caught.value.code == "not_found"


def test_light_parse_wraps_androguard_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(path: str) -> Any:
        raise RuntimeError("bad zip")

    _install_androguard(monkeypatch, apk=boom)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._apk(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"
    assert "failed to parse APK" in caught.value.message


# ---------------------------------------------------------------------------
# _parsed (full DEX analysis) caching + errors
# ---------------------------------------------------------------------------


def test_full_parse_caches_and_wraps_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def fake_analyze(path: str) -> tuple[Any, Any, Any]:
        calls.append(path)
        return ("APK", "DEX", "ANALYSIS")

    _install_androguard(monkeypatch, analyze=fake_analyze)
    client = ApkClient()
    apk_path = _apk_file(tmp_path)

    parsed = client._parsed(apk_path)
    assert isinstance(parsed, _ParsedApk)
    assert parsed.analysis == "ANALYSIS"
    # Second call hits the cache: analyze runs once.
    assert client._parsed(apk_path) is parsed
    assert calls == [str(apk_path.resolve())]


def test_full_parse_error_is_backend_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(path: str) -> Any:
        raise ValueError("no dex")

    _install_androguard(monkeypatch, analyze=boom)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._parsed(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"
    assert "failed to analyze APK" in caught.value.message


def test_full_parse_evicts_under_the_cache_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_androguard(monkeypatch, analyze=lambda path: (path, "DEX", object()))
    monkeypatch.setattr(apk_mod, "_CACHE_LIMIT", 1)
    client = ApkClient()

    client._parsed(_apk_file(tmp_path, "a.apk"))
    client._parsed(_apk_file(tmp_path, "b.apk"))
    assert len(ApkClient._full_cache) == 1


# ---------------------------------------------------------------------------
# method edge/error branches (driven with fakes over _apk/_parsed)
# ---------------------------------------------------------------------------


class _FakeManifestApk:
    def get_android_manifest_axml(self) -> Any:
        raise RuntimeError("axml broken")


def test_manifest_wraps_a_decode_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeManifestApk())
    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"
    assert "failed to decode manifest" in caught.value.message


class _FakePermApk:
    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        raise AttributeError("old androguard")


def test_permissions_falls_back_when_requested_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakePermApk())
    payload = client.permissions(tmp_path / "app.apk")
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["requested_permissions"] == payload["permissions"]


class _BadCert:
    @property
    def subject(self) -> str:
        raise RuntimeError("unreadable cert")


class _FakeCertApk:
    def get_signature_names(self) -> list[str]:
        raise RuntimeError("no v1 block")

    def get_certificates(self) -> list[Any]:
        return [_BadCert()]


def test_certificates_tolerates_missing_names_and_bad_certs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeCertApk())
    payload = client.certificates(tmp_path / "app.apk")
    assert payload["signature_files"] == []
    assert payload["certificates"] == []
    assert payload["v1_signed"] is False


class _FakeFilesApk:
    def get_files(self) -> list[str]:
        # "lib/foo" has only two segments -> the abi branch is skipped.
        return ["lib/arm64-v8a/libnative.so", "lib/foo", "res/layout/main.xml"]


def test_native_libs_records_abis_and_skips_short_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeFilesApk())
    payload = client.native_libs(tmp_path / "app.apk")
    assert payload["abis"] == ["arm64-v8a"]
    assert "lib/arm64-v8a/libnative.so" in payload["native_libs"]
    assert "lib/foo" in payload["native_libs"]


def test_native_libs_flags_when_the_list_is_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apk_mod, "_MAX_NATIVE_LIBS", 1)

    class _ManyLibsApk:
        def get_files(self) -> list[str]:
            return ["lib/arm64-v8a/a.so", "lib/arm64-v8a/b.so"]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _ManyLibsApk())
    payload = client.native_libs(tmp_path / "app.apk")
    assert payload["count"] == 1
    assert payload["has_more"] is True


class _FakeClass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeClassAnalysis:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def test_classes_skips_external_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parsed = _FakeClassAnalysis(
        [_FakeClass("Lapp/A;"), _FakeClass("Ljava/lang/Object;", external=True)]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.classes(tmp_path / "app.apk")
    assert payload["classes"] == ["Lapp/A;"]
    assert payload["total"] == 1


class _FakeMethodClass:
    def __init__(self, name: str) -> None:
        self.name = name

    def get_methods(self) -> list[Any]:
        return []


class _FakeMethodAnalysis:
    def __init__(self, classes: list[_FakeMethodClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeMethodClass]:
        return self._classes


def test_methods_requires_a_name_and_reports_missing_classes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeMethodAnalysis([_FakeMethodClass("Lapp/Foo;")])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    with pytest.raises(ApkError) as blank:
        client.methods(tmp_path / "app.apk", "   ")
    assert blank.value.code == "invalid_params"

    with pytest.raises(ApkError) as missing:
        client.methods(tmp_path / "app.apk", "app.Nope")
    assert missing.value.code == "not_found"


class _FakeXrefMethod:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[Any]:
        return []


class _FakeXrefAnalysis:
    def __init__(self, methods: list[Any]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[Any]:
        return self._methods


def test_xrefs_requires_a_name_and_skips_nonmatching_methods(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeXrefAnalysis(
        [
            _FakeXrefMethod("decrypt", external=True),  # external -> skipped
            _FakeXrefMethod("other"),  # name mismatch -> skipped
        ]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    with pytest.raises(ApkError) as blank:
        client.xrefs(tmp_path / "app.apk", "  ")
    assert blank.value.code == "invalid_params"

    payload = client.xrefs(tmp_path / "app.apk", "decrypt")
    assert payload["callers"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False


# ---------------------------------------------------------------------------
# success payloads + scan caps
# ---------------------------------------------------------------------------


class _FakeOpenApk:
    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.2.3"

    def get_androidversion_code(self) -> str:
        return "123"

    def get_min_sdk_version(self) -> str:
        return "24"

    def get_target_sdk_version(self) -> str:
        return "34"

    def get_main_activity(self) -> str:
        return "com.example.app.Main"

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_files(self) -> list[str]:
        return ["lib/arm64-v8a/libx.so", "lib/x86/liby.so", "classes.dex"]


def test_open_reports_package_and_native_abis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeOpenApk())
    payload = client.open(tmp_path / "app.apk")
    assert payload["opened"] is True
    assert payload["package"] == "com.example.app"
    assert payload["permission_count"] == 1
    assert payload["native_abis"] == ["arm64-v8a", "x86"]


class _FakeComponentsApk:
    def get_activities(self) -> list[str]:
        return ["c.MainActivity"]

    def get_services(self) -> list[str]:
        return ["c.SyncService"]

    def get_receivers(self) -> list[str]:
        return ["c.BootReceiver"]

    def get_providers(self) -> list[str]:
        return ["c.FileProvider"]

    def get_main_activity(self) -> str:
        return "c.MainActivity"


def test_components_lists_each_kind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeComponentsApk())
    payload = client.components(tmp_path / "app.apk")
    assert payload["activities"] == ["c.MainActivity"]
    assert payload["services"] == ["c.SyncService"]
    assert payload["receivers"] == ["c.BootReceiver"]
    assert payload["providers"] == ["c.FileProvider"]
    assert payload["has_more"] is False


class _GoodCert:
    subject = "CN=Example"
    issuer = "CN=Example CA"
    serial_number = 42
    sha256_fingerprint = "ab" * 32


class _NamedCertApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[Any]:
        return [_GoodCert()]


def test_certificates_reports_names_and_a_parsed_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _NamedCertApk())
    payload = client.certificates(tmp_path / "app.apk")
    assert payload["signature_files"] == ["META-INF/CERT.RSA"]
    assert payload["v1_signed"] is True
    assert payload["certificates"][0]["subject"] == "CN=Example"
    assert payload["certificates"][0]["sha256"] == "ab" * 32


def test_certificates_caps_names_and_certs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_mod, "_MAX_CERTIFICATES", 1)

    class _ManyApk:
        def get_signature_names(self) -> list[str]:
            return ["a.RSA", "b.RSA"]

        def get_certificates(self) -> list[Any]:
            return [_GoodCert(), _GoodCert()]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _ManyApk())
    payload = client.certificates(tmp_path / "app.apk")
    assert len(payload["signature_files"]) == 1
    assert len(payload["certificates"]) == 1
    assert payload["has_more"] is True


class _StringItem:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeStringAnalysis:
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = values

    def get_strings(self) -> list[_StringItem]:
        return [_StringItem(v) for v in self._values]


def test_strings_dedupes_sorts_and_flags_scan_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apk_mod, "_MAX_STRINGS_COLLECT", 2)
    parsed = _FakeStringAnalysis(["zeta", "alpha", "beta"])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.strings(tmp_path / "app.apk", offset=0, limit=10)
    assert payload["scan_capped"] is True
    assert payload["total"] == 2
    assert payload["strings"] == sorted(payload["strings"])


def test_strings_without_a_scan_cap_enumerates_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeStringAnalysis(["b", "a", "a"])  # a duplicate is deduped
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.strings(tmp_path / "app.apk", offset=0, limit=10)
    assert payload["scan_capped"] is False
    assert payload["strings"] == ["a", "b"]
    assert payload["has_more"] is False


def test_classes_flags_the_scan_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_mod, "_MAX_CLASSES_COLLECT", 1)
    parsed = _FakeClassAnalysis([_FakeClass("Lb;"), _FakeClass("La;")])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.classes(tmp_path / "app.apk")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


class _MethodItem:
    def __init__(self, name: str) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"


class _MethodHost:
    def __init__(self, count: int) -> None:
        self.name = "Lapp/Foo;"
        self._methods = [_MethodItem(f"m{i}") for i in range(count)]

    def get_methods(self) -> list[_MethodItem]:
        return self._methods


class _MethodHostAnalysis:
    def __init__(self, host: _MethodHost) -> None:
        self.analysis = self
        self._host = host

    def get_classes(self) -> list[_MethodHost]:
        return [self._host]


def test_methods_returns_a_page_and_flags_the_scan_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apk_mod, "_MAX_METHODS_COLLECT", 1)
    parsed = _MethodHostAnalysis(_MethodHost(3))
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.methods(tmp_path / "app.apk", "Lapp/Foo;", offset=0, limit=10)
    assert payload["class_name"] == "Lapp/Foo;"
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


class _CallSite:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcaller/C{index};"
        self.name = "invoke"


class _XrefMethodWithCallers:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[Any]:
        return [(None, _CallSite(i), i) for i in range(self._callers)]


def test_xrefs_collects_callers_and_reports_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeXrefAnalysis([_XrefMethodWithCallers("decrypt", 3)])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True
    assert payload["callers"][0]["class"].startswith("Lcaller/C")


def test_xrefs_returns_every_caller_when_under_the_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _FakeXrefAnalysis([_XrefMethodWithCallers("decrypt", 1)])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=100)
    assert payload["count"] == 1
    assert payload["has_more"] is False
