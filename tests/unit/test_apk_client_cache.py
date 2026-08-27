"""ApkClient parse / cache / require paths with a stand-in androguard.

The field-shape tests in ``test_apk_fields.py`` monkeypatch ``_apk`` / ``_parsed``
away, so the real bodies -- the availability and not-found guards, the light and
full parse caches with their eviction, and the backend_error envelopes around a
failed parse -- never run in CI. androguard cannot be imported here, so this
installs a minimal fake module tree and drives those arcs directly.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.apk.client as apkmod
from headless_re_mcp.backends.apk.client import ApkClient, ApkError, _dotted_to_smali


# --------------------------------------------------------------------------
# Minimal androguard stand-ins.
# --------------------------------------------------------------------------
class _Axml:
    def __init__(self, xml: bytes | None = b"<manifest package='com.example.app'/>") -> None:
        self._xml = xml

    def get_xml(self) -> bytes:
        if self._xml is None:
            raise RuntimeError("axml decode failed")
        return self._xml


class _Cert:
    def __init__(self, tag: str) -> None:
        self.subject = f"CN={tag}"
        self.issuer = f"CN={tag}-CA"
        self.serial_number = 1234
        self.sha256_fingerprint = tag * 4


class _BoomText:
    def __str__(self) -> str:
        raise RuntimeError("certificate field decode failed")


class _BoomCert:
    subject = _BoomText()
    issuer = ""
    serial_number = 0


class _FakeApk:
    """A permissive APK: every accessor returns something plausible.

    Individual tests override single methods by subclassing rather than adding
    another flag, keeping each scenario's intent local to its test.
    """

    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.2.3"

    def get_androidversion_code(self) -> str:
        return "123"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "34"

    def get_main_activity(self) -> str:
        return "com.example.app.Main"

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.CAMERA"]

    def get_files(self) -> list[str]:
        return [
            "lib/arm64-v8a/libnative.so",
            "lib/armeabi-v7a/libnative.so",
            "classes.dex",
            "res/layout/main.xml",
        ]

    def get_android_manifest_axml(self) -> _Axml:
        return _Axml()

    def get_signature_names(self) -> list[str]:
        return ["META-INF/CERT.RSA"]

    def get_certificates(self) -> list[Any]:
        return [_Cert("a")]

    def get_activities(self) -> list[str]:
        return ["com.example.app.Main", "com.example.app.Second"]

    def get_services(self) -> list[str]:
        return ["com.example.app.Svc"]

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []


class _Klass:
    def __init__(self, name: str, *, external: bool = False, methods: tuple[Any, ...] = ()) -> None:
        self.name = name
        self._external = external
        self._methods = list(methods)

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[Any]:
        return self._methods


class _Meth:
    def __init__(self, name: str, *, external: bool = False, xrefs: tuple[Any, ...] = ()) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"
        self._external = external
        self._xrefs = list(xrefs)

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[Any]:
        return self._xrefs


class _Str:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _Analysis:
    def __init__(
        self,
        *,
        classes: tuple[Any, ...] = (),
        methods: tuple[Any, ...] = (),
        strings: tuple[Any, ...] = (),
    ) -> None:
        self._classes = list(classes)
        self._methods = list(methods)
        self._strings = list(strings)

    def get_classes(self) -> list[Any]:
        return self._classes

    def get_methods(self) -> list[Any]:
        return self._methods

    def get_strings(self) -> list[Any]:
        return self._strings


@pytest.fixture(autouse=True)
def _clear_caches() -> Any:
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    apk_factory: Any = None,
    analyze_factory: Any = None,
) -> None:
    root = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    apk_pkg = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    apk_pkg.APK = apk_factory or (lambda path: _FakeApk())  # type: ignore[attr-defined]
    misc.AnalyzeAPK = analyze_factory or (  # type: ignore[attr-defined]
        lambda path: (_FakeApk(), object(), _Analysis())
    )
    core.apk = apk_pkg  # type: ignore[attr-defined]
    root.core = core  # type: ignore[attr-defined]
    root.misc = misc  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", root)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.apk", apk_pkg)
    monkeypatch.setitem(sys.modules, "androguard.misc", misc)


def _client(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> ApkClient:
    _install(monkeypatch, **kwargs)
    client = ApkClient()
    assert client.available is True
    return client


def _apk_file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04apk")
    return path


# --------------------------------------------------------------------------
# __init__ / release / _require.
# --------------------------------------------------------------------------
def test_available_when_the_module_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch)
    assert ApkClient().available is True


def test_require_reports_capability_unavailable_without_androguard(tmp_path: Path) -> None:
    client = ApkClient()
    if client.available:
        pytest.skip("androguard installed — degradation path not exercised (skip != pass)")
    with pytest.raises(ApkError) as info:
        client.open(_apk_file(tmp_path))
    assert info.value.code == "capability_unavailable"


def test_require_reports_not_found_for_a_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    with pytest.raises(ApkError) as info:
        client.open(tmp_path / "does-not-exist.apk")
    assert info.value.code == "not_found"


def test_release_survives_a_path_that_cannot_be_resolved() -> None:
    class _BadPath:
        def expanduser(self) -> _BadPath:
            return self

        def resolve(self) -> Path:
            raise OSError("cannot resolve")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


def test_release_drops_cached_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    apk = _apk_file(tmp_path)
    client.open(apk)
    client.classes(apk)
    assert ApkClient._light_cache and ApkClient._full_cache
    assert ApkClient.release(apk) is True
    assert not ApkClient._light_cache
    assert not ApkClient._full_cache


def test_release_reports_false_when_nothing_was_cached(tmp_path: Path) -> None:
    assert ApkClient.release(_apk_file(tmp_path)) is False


# --------------------------------------------------------------------------
# Light cache (_apk).
# --------------------------------------------------------------------------
def test_light_parse_is_cached_and_not_repeated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def factory(path: str) -> _FakeApk:
        calls.append(path)
        return _FakeApk()

    client = _client(monkeypatch, apk_factory=factory)
    apk = _apk_file(tmp_path)
    client.open(apk)
    client.open(apk)
    assert len(calls) == 1


def test_light_cache_evicts_beyond_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    for index in range(apkmod._CACHE_LIMIT + 2):
        client.open(_apk_file(tmp_path, f"app{index}.apk"))
    assert len(ApkClient._light_cache) == apkmod._CACHE_LIMIT


def test_light_parse_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def factory(path: str) -> _FakeApk:
        raise ValueError("bad zip central directory")

    client = _client(monkeypatch, apk_factory=factory)
    with pytest.raises(ApkError) as info:
        client.open(_apk_file(tmp_path))
    assert info.value.code == "backend_error"
    assert "failed to parse APK" in info.value.message


# --------------------------------------------------------------------------
# Full cache (_parsed).
# --------------------------------------------------------------------------
def test_full_parse_is_cached_and_not_repeated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def analyze(path: str) -> tuple[Any, Any, _Analysis]:
        calls.append(path)
        return _FakeApk(), object(), _Analysis(classes=(_Klass("La;"),))

    client = _client(monkeypatch, analyze_factory=analyze)
    apk = _apk_file(tmp_path)
    client.classes(apk)
    client.classes(apk)
    assert len(calls) == 1


def test_full_cache_evicts_beyond_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    for index in range(apkmod._CACHE_LIMIT + 2):
        client.classes(_apk_file(tmp_path, f"app{index}.apk"))
    assert len(ApkClient._full_cache) == apkmod._CACHE_LIMIT


def test_full_parse_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def analyze(path: str) -> tuple[Any, Any, _Analysis]:
        raise RuntimeError("dex analysis blew up")

    client = _client(monkeypatch, analyze_factory=analyze)
    with pytest.raises(ApkError) as info:
        client.classes(_apk_file(tmp_path))
    assert info.value.code == "backend_error"
    assert "failed to analyze APK" in info.value.message


# --------------------------------------------------------------------------
# open / manifest / permissions / certificates / components / native_libs.
# --------------------------------------------------------------------------
def test_open_reports_manifest_facts_and_abis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    payload = client.open(_apk_file(tmp_path))
    assert payload["opened"] is True
    assert payload["package"] == "com.example.app"
    assert payload["native_abis"] == ["arm64-v8a", "armeabi-v7a"]
    assert payload["permission_count"] == 1


def test_manifest_decode_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BadManifest(_FakeApk):
        def get_android_manifest_axml(self) -> _Axml:
            return _Axml(None)

    client = _client(monkeypatch, apk_factory=lambda path: _BadManifest())
    with pytest.raises(ApkError) as info:
        client.manifest(_apk_file(tmp_path))
    assert info.value.code == "backend_error"
    assert "failed to decode manifest" in info.value.message


def test_permissions_falls_back_when_requested_permissions_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _OldApk(_FakeApk):
        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("older androguard has no get_requested_permissions")

    client = _client(monkeypatch, apk_factory=lambda path: _OldApk())
    payload = client.permissions(_apk_file(tmp_path))
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["requested_permissions"] == payload["permissions"]


def test_certificates_reports_files_and_v1_signed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    payload = client.certificates(_apk_file(tmp_path))
    assert payload["v1_signed"] is True
    assert payload["signature_files"] == ["META-INF/CERT.RSA"]
    assert payload["certificates"][0]["subject"] == "CN=a"


def test_certificates_tolerate_missing_signature_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _NoNames(_FakeApk):
        def get_signature_names(self) -> list[str]:
            raise RuntimeError("unsupported scheme")

    client = _client(monkeypatch, apk_factory=lambda path: _NoNames())
    payload = client.certificates(_apk_file(tmp_path))
    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False


def test_certificates_skip_a_row_that_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomCerts(_FakeApk):
        def get_certificates(self) -> list[Any]:
            return [_BoomCert()]

    client = _client(monkeypatch, apk_factory=lambda path: _BoomCerts())
    payload = client.certificates(_apk_file(tmp_path))
    assert payload["certificates"] == []


def test_certificates_cap_both_lists_and_report_more(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apkmod, "_MAX_CERTIFICATES", 1)

    class _ManyCerts(_FakeApk):
        def get_signature_names(self) -> list[str]:
            return ["META-INF/A.RSA", "META-INF/B.RSA"]

        def get_certificates(self) -> list[Any]:
            return [_Cert("a"), _Cert("b")]

    client = _client(monkeypatch, apk_factory=lambda path: _ManyCerts())
    payload = client.certificates(_apk_file(tmp_path))
    assert len(payload["signature_files"]) == 1
    assert len(payload["certificates"]) == 1
    assert payload["has_more"] is True


def test_components_lists_each_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    payload = client.components(_apk_file(tmp_path))
    assert payload["activities"] == ["com.example.app.Main", "com.example.app.Second"]
    assert payload["services"] == ["com.example.app.Svc"]
    assert payload["receivers"] == []
    assert payload["has_more"] is False


def test_native_libs_group_by_abi_and_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apkmod, "_MAX_NATIVE_LIBS", 1)

    class _Libs(_FakeApk):
        def get_files(self) -> list[str]:
            return [
                "lib/arm64-v8a/liba.so",
                "lib/arm64-v8a/libb.so",
                "assets/data.bin",
            ]

    client = _client(monkeypatch, apk_factory=lambda path: _Libs())
    payload = client.native_libs(_apk_file(tmp_path))
    assert payload["abis"] == ["arm64-v8a"]
    assert payload["count"] == 1
    assert payload["has_more"] is True


# --------------------------------------------------------------------------
# classes / methods / strings / xrefs scan and validation guards.
# --------------------------------------------------------------------------
def test_classes_skip_external_and_report_scan_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apkmod, "_MAX_CLASSES_COLLECT", 2)
    analysis = _Analysis(
        classes=(
            _Klass("Lc/A;"),
            _Klass("Lc/External;", external=True),
            _Klass("Lc/B;"),
            _Klass("Lc/C;"),
        )
    )
    client = _client(monkeypatch, analyze_factory=lambda path: (_FakeApk(), object(), analysis))
    payload = client.classes(_apk_file(tmp_path))
    assert "Lc/External;" not in payload["classes"]
    assert payload["scan_capped"] is True
    assert payload["total"] == 2


def test_methods_requires_a_class_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    with pytest.raises(ApkError) as info:
        client.methods(_apk_file(tmp_path), "   ")
    assert info.value.code == "invalid_params"


def test_methods_reports_a_missing_class_as_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analysis = _Analysis(classes=(_Klass("Lcom/example/Foo;"),))
    client = _client(monkeypatch, analyze_factory=lambda path: (_FakeApk(), object(), analysis))
    with pytest.raises(ApkError) as info:
        client.methods(_apk_file(tmp_path), "com.example.Absent")
    assert info.value.code == "not_found"


def test_methods_resolve_a_dotted_class_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    klass = _Klass("Lcom/example/Foo;", methods=(_Meth("decrypt"), _Meth("encrypt")))
    analysis = _Analysis(classes=(klass,))
    client = _client(monkeypatch, analyze_factory=lambda path: (_FakeApk(), object(), analysis))
    payload = client.methods(_apk_file(tmp_path), "com.example.Foo")
    assert payload["class_name"] == "Lcom/example/Foo;"
    assert payload["count"] == 2


def test_methods_report_scan_cap_when_a_class_has_too_many(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apkmod, "_MAX_METHODS_COLLECT", 1)
    klass = _Klass("Lcom/example/Foo;", methods=(_Meth("a"), _Meth("b"), _Meth("c")))
    analysis = _Analysis(classes=(klass,))
    client = _client(monkeypatch, analyze_factory=lambda path: (_FakeApk(), object(), analysis))
    payload = client.methods(_apk_file(tmp_path), "com.example.Foo")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_permissions_report_more_when_the_list_overflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apkmod, "_MAX_PERMISSIONS", 1)

    class _ManyPerms(_FakeApk):
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET", "android.permission.CAMERA"]

    client = _client(monkeypatch, apk_factory=lambda path: _ManyPerms())
    payload = client.permissions(_apk_file(tmp_path))
    assert len(payload["permissions"]) == 1
    assert payload["has_more"] is True


def test_strings_dedupe_sort_and_report_scan_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apkmod, "_MAX_STRINGS_COLLECT", 2)
    analysis = _Analysis(strings=(_Str("zeta"), _Str("alpha"), _Str("beta")))
    client = _client(monkeypatch, analyze_factory=lambda path: (_FakeApk(), object(), analysis))
    payload = client.strings(_apk_file(tmp_path))
    assert payload["scan_capped"] is True
    assert payload["strings"] == sorted(payload["strings"])


def test_xrefs_requires_a_method_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch)
    with pytest.raises(ApkError) as info:
        client.xrefs(_apk_file(tmp_path), "  ")
    assert info.value.code == "invalid_params"


# --------------------------------------------------------------------------
# _dotted_to_smali both shapes.
# --------------------------------------------------------------------------
def test_dotted_to_smali_leaves_a_descriptor_untouched() -> None:
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"


def test_dotted_to_smali_converts_a_dotted_name() -> None:
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
