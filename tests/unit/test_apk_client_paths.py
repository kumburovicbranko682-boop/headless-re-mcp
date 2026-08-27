"""Cache, guard and fallback branches of the APK (androguard) backend.

The real androguard objects are faked so the parse/cache lifecycle and every
read method's error and version-fallback branches are exercised without a real
APK: the process-wide caches serve hits and evict the oldest parse, a missing
androguard degrades to capability_unavailable, a non-file is not_found, and each
reader tolerates the androguard-version differences (missing requested
permissions, signature names, certificate fields) and bounds its own scan.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
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
def _clear_apk_caches() -> Any:
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04apk")
    return path


def _client() -> ApkClient:
    client = ApkClient()
    client._available = True
    return client


# ----------------------------------------------------------------------------
# Fakes for the androguard APK / AnalyzeAPK surfaces.
# ----------------------------------------------------------------------------
class _FakeAxml:
    def __init__(self, xml: bytes = b"<manifest/>", raise_exc: BaseException | None = None) -> None:
        self._xml = xml
        self._raise = raise_exc

    def get_xml(self) -> bytes:
        if self._raise is not None:
            raise self._raise
        return self._xml


class _FakeApk:
    """A minimal androguard APK, with per-instance overrides for the awkward
    version-dependent methods."""

    def __init__(self, **overrides: Any) -> None:
        self._overrides = overrides

    def _get(self, key: str, default: Any) -> Any:
        value = self._overrides.get(key, default)
        if isinstance(value, BaseException):
            raise value
        return value

    def get_package(self) -> Any:
        return self._get("package", "com.example.app")

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "33"

    def get_main_activity(self) -> str:
        return "com.example.app.Main"

    def get_permissions(self) -> list[str]:
        return self._get("permissions", ["android.permission.INTERNET"])

    def get_requested_permissions(self) -> list[str]:
        return self._get("requested", ["android.permission.INTERNET"])

    def get_files(self) -> list[str]:
        return self._get("files", ["lib/arm64-v8a/libx.so", "classes.dex"])

    def get_android_manifest_axml(self) -> _FakeAxml:
        return self._get("axml", _FakeAxml())

    def get_signature_names(self) -> list[str]:
        return self._get("signature_names", ["META-INF/CERT.RSA"])

    def get_certificates(self) -> list[Any]:
        return self._get("certificates", [])

    def get_activities(self) -> list[str]:
        return ["com.example.app.Main"]

    def get_services(self) -> list[str]:
        return []

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []


def _patch_apk(monkeypatch: Any, factory: Any) -> None:
    monkeypatch.setattr("androguard.core.apk.APK", factory)


def _patch_analyze(monkeypatch: Any, apk: Any, analysis: Any) -> None:
    monkeypatch.setattr(
        "androguard.misc.AnalyzeAPK",
        lambda path: (apk, SimpleNamespace(), analysis),
    )


# ----------------------------------------------------------------------------
# Construction / availability.
# ----------------------------------------------------------------------------
def test_missing_androguard_degrades(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setitem(sys.modules, "androguard", None)
    client = ApkClient()
    assert client.available is False
    with pytest.raises(ApkError) as info:
        client.open(_file(tmp_path))
    assert info.value.code == "capability_unavailable"


def test_available_property_reflects_import() -> None:
    # androguard is installed in this environment, so a plain construction is
    # available; the missing case is covered above.
    assert ApkClient().available is True


# ----------------------------------------------------------------------------
# release(): OSError while resolving is swallowed.
# ----------------------------------------------------------------------------
def test_release_returns_false_when_the_path_cannot_resolve() -> None:
    class _BadPath:
        def expanduser(self) -> Any:
            raise OSError("bad path")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


# ----------------------------------------------------------------------------
# _require(): capability gap and not_found.
# ----------------------------------------------------------------------------
def test_require_rejects_a_missing_file() -> None:
    client = _client()
    with pytest.raises(ApkError) as info:
        client.open(Path("/no/such/file.apk"))
    assert info.value.code == "not_found"


# ----------------------------------------------------------------------------
# _apk(): parse, cache-hit, parse failure, eviction.
# ----------------------------------------------------------------------------
def test_apk_parse_is_cached_and_reused(monkeypatch: Any, tmp_path: Path) -> None:
    calls: list[str] = []

    def factory(path: str) -> _FakeApk:
        calls.append(path)
        return _FakeApk()

    _patch_apk(monkeypatch, factory)
    client = _client()
    path = _file(tmp_path)
    first = client._apk(path)
    second = client._apk(path)
    assert first is second
    assert len(calls) == 1  # the second call served from the cache


def test_apk_parse_failure_is_backend_error(monkeypatch: Any, tmp_path: Path) -> None:
    def factory(path: str) -> _FakeApk:
        raise ValueError("bad zip")

    _patch_apk(monkeypatch, factory)
    client = _client()
    with pytest.raises(ApkError) as info:
        client._apk(_file(tmp_path))
    assert info.value.code == "backend_error"


def test_light_cache_evicts_the_oldest_parse(monkeypatch: Any, tmp_path: Path) -> None:
    _patch_apk(monkeypatch, lambda path: _FakeApk())
    client = _client()
    for index in range(_CACHE_LIMIT + 2):
        client._apk(_file(tmp_path, f"app{index}.apk"))
    assert len(ApkClient._light_cache) == _CACHE_LIMIT


# ----------------------------------------------------------------------------
# _parsed(): analyze, cache-hit, analyze failure, eviction, _ParsedApk shape.
# ----------------------------------------------------------------------------
def test_parsed_analysis_is_cached_and_reused(monkeypatch: Any, tmp_path: Path) -> None:
    calls: list[str] = []

    def analyze(path: str) -> tuple[Any, Any, Any]:
        calls.append(path)
        return _FakeApk(), SimpleNamespace(), SimpleNamespace()

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", analyze)
    client = _client()
    path = _file(tmp_path)
    first = client._parsed(path)
    second = client._parsed(path)
    assert isinstance(first, _ParsedApk)
    assert first is second
    assert len(calls) == 1


def test_parsed_analysis_failure_is_backend_error(monkeypatch: Any, tmp_path: Path) -> None:
    def analyze(path: str) -> tuple[Any, Any, Any]:
        raise RuntimeError("dex corrupt")

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", analyze)
    client = _client()
    with pytest.raises(ApkError) as info:
        client._parsed(_file(tmp_path))
    assert info.value.code == "backend_error"


def test_full_cache_evicts_the_oldest_analysis(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "androguard.misc.AnalyzeAPK",
        lambda path: (_FakeApk(), SimpleNamespace(), SimpleNamespace()),
    )
    client = _client()
    for index in range(_CACHE_LIMIT + 2):
        client._parsed(_file(tmp_path, f"app{index}.apk"))
    assert len(ApkClient._full_cache) == _CACHE_LIMIT


# ----------------------------------------------------------------------------
# open(): success shape and the not-an-APK guard.
# ----------------------------------------------------------------------------
def test_open_reports_package_and_abis(monkeypatch: Any, tmp_path: Path) -> None:
    _patch_apk(
        monkeypatch,
        lambda path: _FakeApk(files=["lib/arm64-v8a/x.so", "lib/x86/y.so", "classes.dex"]),
    )
    payload = _client().open(_file(tmp_path))
    assert payload["opened"] is True
    assert payload["package"] == "com.example.app"
    assert payload["native_abis"] == ["arm64-v8a", "x86"]


def test_open_refuses_an_archive_with_no_package(monkeypatch: Any, tmp_path: Path) -> None:
    _patch_apk(monkeypatch, lambda path: _FakeApk(package=None))
    with pytest.raises(ApkError) as info:
        _client().open(_file(tmp_path))
    assert info.value.code == "backend_error"
    assert info.value.details["opened"] is False


# ----------------------------------------------------------------------------
# manifest(): decode failure.
# ----------------------------------------------------------------------------
def test_manifest_decode_failure_is_backend_error(monkeypatch: Any, tmp_path: Path) -> None:
    _patch_apk(
        monkeypatch,
        lambda path: _FakeApk(axml=_FakeAxml(raise_exc=RuntimeError("axml broken"))),
    )
    with pytest.raises(ApkError) as info:
        _client().manifest(_file(tmp_path))
    assert info.value.code == "backend_error"


# ----------------------------------------------------------------------------
# permissions(): fallback when get_requested_permissions is unavailable.
# ----------------------------------------------------------------------------
def test_permissions_falls_back_when_requested_is_unavailable(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _patch_apk(
        monkeypatch,
        lambda path: _FakeApk(
            permissions=["android.permission.INTERNET"],
            requested=AttributeError("older androguard"),
        ),
    )
    result = _client().permissions(_file(tmp_path))
    # The declared list stands in for requested when androguard cannot supply it.
    assert result["permissions"] == ["android.permission.INTERNET"]
    assert result["requested_permissions"] == ["android.permission.INTERNET"]


# ----------------------------------------------------------------------------
# certificates(): missing signature names and a certificate that fails to read.
# ----------------------------------------------------------------------------
def test_certificates_tolerate_missing_signature_names(monkeypatch: Any, tmp_path: Path) -> None:
    class _GoodCert:
        subject = "CN=Good"
        issuer = "CN=Good"
        serial_number = 1
        sha256_fingerprint = "aa"

    class _BadCert:
        issuer = "CN=Bad"
        serial_number = 2

        @property
        def subject(self) -> str:
            raise RuntimeError("unreadable certificate")

    _patch_apk(
        monkeypatch,
        lambda path: _FakeApk(
            signature_names=RuntimeError("no v1 block"),
            certificates=[_GoodCert(), _BadCert()],
        ),
    )
    result = _client().certificates(_file(tmp_path))
    assert result["signature_files"] == []
    assert result["v1_signed"] is False
    # The good certificate is kept; the unreadable one is skipped, not fatal.
    assert len(result["certificates"]) == 1
    assert result["certificates"][0]["subject"] == "CN=Good"


# ----------------------------------------------------------------------------
# Fake analysis for classes / methods / xrefs.
# ----------------------------------------------------------------------------
class _Method:
    def __init__(self, name: str, *, external: bool = False, callers: int = 0) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, Any, int]]:
        call = SimpleNamespace(class_name="Lcom/example/Caller;", name="invoke")
        return [(None, call, i) for i in range(self._callers)]


class _Klass:
    def __init__(
        self, name: str, *, external: bool = False, methods: list[_Method] | None = None
    ) -> None:
        self.name = name
        self._external = external
        self._methods = methods or []

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[_Method]:
        return self._methods


def _parsed_with(monkeypatch: Any, **analysis: Any) -> None:
    fake = SimpleNamespace(
        get_classes=lambda: analysis.get("classes", []),
        get_methods=lambda: analysis.get("methods", []),
        get_strings=lambda: analysis.get("strings", []),
    )
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _ParsedApk(None, fake, None))


# ----------------------------------------------------------------------------
# classes(): external classes are skipped.
# ----------------------------------------------------------------------------
def test_classes_skips_external_classes(monkeypatch: Any, tmp_path: Path) -> None:
    _parsed_with(
        monkeypatch,
        classes=[_Klass("Lext/Thing;", external=True), _Klass("Lcom/app/A;")],
    )
    result = _client().classes(_file(tmp_path))
    assert result["classes"] == ["Lcom/app/A;"]
    assert result["total"] == 1


# ----------------------------------------------------------------------------
# methods(): class_name guard, not_found, and dotted/smali resolution.
# ----------------------------------------------------------------------------
def test_methods_requires_a_class_name(monkeypatch: Any, tmp_path: Path) -> None:
    _parsed_with(monkeypatch, classes=[])
    with pytest.raises(ApkError) as info:
        _client().methods(_file(tmp_path), "   ")
    assert info.value.code == "invalid_params"


def test_methods_reports_an_unknown_class(monkeypatch: Any, tmp_path: Path) -> None:
    _parsed_with(monkeypatch, classes=[_Klass("Lcom/app/A;")])
    with pytest.raises(ApkError) as info:
        _client().methods(_file(tmp_path), "com.app.Missing")
    assert info.value.code == "not_found"


def test_methods_resolves_a_dotted_class_name(monkeypatch: Any, tmp_path: Path) -> None:
    klass = _Klass("Lcom/app/A;", methods=[_Method("run")])
    _parsed_with(monkeypatch, classes=[klass])
    result = _client().methods(_file(tmp_path), "com.app.A")
    assert result["class_name"] == "Lcom/app/A;"
    assert [m["name"] for m in result["methods"]] == ["run"]


# ----------------------------------------------------------------------------
# xrefs(): method_name guard and non-matching methods are skipped.
# ----------------------------------------------------------------------------
def test_xrefs_requires_a_method_name(monkeypatch: Any, tmp_path: Path) -> None:
    _parsed_with(monkeypatch, methods=[])
    with pytest.raises(ApkError) as info:
        _client().xrefs(_file(tmp_path), "  ")
    assert info.value.code == "invalid_params"


def test_xrefs_skips_external_and_mismatched_methods(monkeypatch: Any, tmp_path: Path) -> None:
    _parsed_with(
        monkeypatch,
        methods=[
            _Method("other", callers=3),
            _Method("decrypt", external=True, callers=3),
            _Method("decrypt", callers=2),
        ],
    )
    result = _client().xrefs(_file(tmp_path), "decrypt")
    # Only the internal method named decrypt contributes callers.
    assert result["count"] == 2
    assert result["has_more"] is False


# ----------------------------------------------------------------------------
# native_libs(): a lib/ entry with no ABI directory contributes no ABI.
# ----------------------------------------------------------------------------
def test_native_libs_tolerate_a_lib_entry_without_an_abi(
    monkeypatch: Any, tmp_path: Path
) -> None:
    _patch_apk(
        monkeypatch,
        lambda path: _FakeApk(
            files=[
                "lib/arm64-v8a/libx.so",
                "lib/notes.txt",  # under lib/ but with no ABI segment
                "classes.dex",  # not under lib/ at all
            ]
        ),
    )
    result = _client().native_libs(_file(tmp_path))
    assert result["abis"] == ["arm64-v8a"]
    # Both lib/ entries are listed; only the well-formed one names an ABI.
    assert result["native_libs"] == ["lib/arm64-v8a/libx.so", "lib/notes.txt"]
    assert result["has_more"] is False


# ----------------------------------------------------------------------------
# _dotted_to_smali: both an already-smali name and a dotted one.
# ----------------------------------------------------------------------------
def test_dotted_to_smali_passthrough_and_conversion() -> None:
    assert _dotted_to_smali("Lcom/app/A;") == "Lcom/app/A;"
    assert _dotted_to_smali("com.app.A") == "Lcom/app/A;"
