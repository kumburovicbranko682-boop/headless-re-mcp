"""ApkClient cache, capability and per-method guard branches.

The field-shape tests pin what each ``apk.*`` call answers with; what is covered
here is the machinery underneath and the guards around it:

* the optional-dependency contract -- a checkout without androguard degrades to
  ``capability_unavailable`` rather than crashing on import;
* the parse cache -- a repeat call on the same path+mtime reuses the parse, the
  cap evicts the oldest, and a session-close ``release`` drops an APK's entries;
* the error contract -- a parse or analysis failure becomes ``backend_error``;
* the honesty guards -- an unreadable manifest/permission/certificate degrades to
  a structured error or an empty-but-labelled result instead of a false success.

Everything runs against injected fakes -- androguard is never really invoked.
"""

from __future__ import annotations

import sys
import types
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
def _clear_caches() -> Any:
    """The parse caches are class-level; isolate every test from its neighbours."""
    with ApkClient._cache_lock:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()
    yield
    with ApkClient._cache_lock:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()


def _fake_androguard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import androguard`` succeed even where the extra is not installed.

    The CI quality job installs only ``.[test,dev,web]``; androguard lives in
    the ``android`` extra. __init__ flips ``_available`` on a successful
    top-level import, and a submodule injected into sys.modules does not create
    that parent, so the real ``_apk``/``_parsed`` gate would raise
    ``capability_unavailable`` there. Seeding sys.modules bypasses the import
    finder entirely, so these cache tests behave the same with or without the
    real package present.
    """
    monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))


def _inject_apk_class(monkeypatch: pytest.MonkeyPatch, apk_class: Any) -> None:
    _fake_androguard(monkeypatch)
    module = types.ModuleType("androguard.core.apk")
    module.APK = apk_class  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard.core.apk", module)


def _inject_analyze(monkeypatch: pytest.MonkeyPatch, func: Any) -> None:
    _fake_androguard(monkeypatch)
    module = types.ModuleType("androguard.misc")
    module.AnalyzeAPK = func  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard.misc", module)


# --------------------------------------------------------------------------
# _ParsedApk / availability
# --------------------------------------------------------------------------
def test_parsed_apk_holds_the_three_handles() -> None:
    apk, analysis, dex = object(), object(), object()
    parsed = _ParsedApk(apk, analysis, dex)
    assert parsed.apk is apk
    assert parsed.analysis is analysis
    assert parsed._dex is dex


def test_missing_androguard_degrades_to_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "androguard", None)
    client = ApkClient()
    assert client.available is False


def test_available_reports_true_when_androguard_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    # androguard is an optional extra the CI quality job does not install, so
    # pin availability to a fake top-level module rather than the real one:
    # __init__ flips _available on a successful ``import androguard``.
    monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))
    assert ApkClient().available is True


# --------------------------------------------------------------------------
# release
# --------------------------------------------------------------------------
def test_release_is_false_when_the_path_cannot_be_resolved() -> None:
    class _BadPath:
        def expanduser(self) -> Any:
            return self

        def resolve(self) -> Any:
            raise OSError("no such filesystem")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


def test_release_drops_cached_entries_for_one_apk(tmp_path: Path) -> None:
    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"PK")
    resolved = str(apk_file.expanduser().resolve())
    with ApkClient._cache_lock:
        ApkClient._light_cache[(resolved, 1)] = object()
        ApkClient._full_cache[(resolved, 1)] = object()  # type: ignore[assignment]
    assert ApkClient.release(apk_file) is True
    assert not any(key[0] == resolved for key in ApkClient._light_cache)
    assert not any(key[0] == resolved for key in ApkClient._full_cache)


def test_release_is_false_when_nothing_was_cached(tmp_path: Path) -> None:
    apk_file = tmp_path / "unseen.apk"
    apk_file.write_bytes(b"PK")
    assert ApkClient.release(apk_file) is False


# --------------------------------------------------------------------------
# _require guards (reached via _apk)
# --------------------------------------------------------------------------
def test_require_refuses_when_androguard_is_unavailable(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = False
    with pytest.raises(ApkError) as caught:
        client._apk(tmp_path / "app.apk")
    assert caught.value.code == "capability_unavailable"


def test_require_reports_a_missing_apk(tmp_path: Path) -> None:
    client = ApkClient()
    client._available = True
    with pytest.raises(ApkError) as caught:
        client._apk(tmp_path / "does-not-exist.apk")
    assert caught.value.code == "not_found"


# --------------------------------------------------------------------------
# _apk parse + cache
# --------------------------------------------------------------------------
class _CountingAPK:
    instances = 0

    def __init__(self, path: str) -> None:
        type(self).instances += 1
        self.path = path


def test_apk_parse_is_cached_by_path_and_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"PK")
    _CountingAPK.instances = 0
    _inject_apk_class(monkeypatch, _CountingAPK)
    client = ApkClient()
    first = client._apk(apk_file)
    second = client._apk(apk_file)
    assert first is second
    assert _CountingAPK.instances == 1


def test_apk_parse_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_file = tmp_path / "corrupt.apk"
    apk_file.write_bytes(b"PK")

    class _FailingAPK:
        def __init__(self, path: str) -> None:
            raise ValueError("not a zip")

    _inject_apk_class(monkeypatch, _FailingAPK)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._apk(apk_file)
    assert caught.value.code == "backend_error"


def test_apk_cache_evicts_the_oldest_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The light cache holds only _CACHE_LIMIT parses; the oldest is dropped."""
    from headless_re_mcp.backends.apk.client import _CACHE_LIMIT

    _inject_apk_class(monkeypatch, _CountingAPK)
    client = ApkClient()
    files = []
    for index in range(_CACHE_LIMIT + 1):
        apk_file = tmp_path / f"app{index}.apk"
        apk_file.write_bytes(b"PK")
        files.append(apk_file)
        client._apk(apk_file)
    assert len(ApkClient._light_cache) == _CACHE_LIMIT
    first_resolved = str(files[0].expanduser().resolve())
    assert not any(key[0] == first_resolved for key in ApkClient._light_cache)


# --------------------------------------------------------------------------
# _parsed analyse + cache
# --------------------------------------------------------------------------
def test_parsed_is_cached_by_path_and_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"PK")
    calls = {"n": 0}

    def _analyze(path: str) -> tuple[Any, Any, Any]:
        calls["n"] += 1
        return (object(), object(), object())

    _inject_analyze(monkeypatch, _analyze)
    client = ApkClient()
    first = client._parsed(apk_file)
    second = client._parsed(apk_file)
    assert first is second
    assert calls["n"] == 1


def test_parsed_cache_evicts_the_oldest_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.apk.client import _CACHE_LIMIT

    def _analyze(path: str) -> tuple[Any, Any, Any]:
        return (object(), object(), object())

    _inject_analyze(monkeypatch, _analyze)
    client = ApkClient()
    files = []
    for index in range(_CACHE_LIMIT + 1):
        apk_file = tmp_path / f"app{index}.apk"
        apk_file.write_bytes(b"PK")
        files.append(apk_file)
        client._parsed(apk_file)
    assert len(ApkClient._full_cache) == _CACHE_LIMIT
    first_resolved = str(files[0].expanduser().resolve())
    assert not any(key[0] == first_resolved for key in ApkClient._full_cache)


def test_parsed_analysis_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk_file = tmp_path / "app.apk"
    apk_file.write_bytes(b"PK")

    def _analyze(path: str) -> tuple[Any, Any, Any]:
        raise RuntimeError("dex parse failed")

    _inject_analyze(monkeypatch, _analyze)
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._parsed(apk_file)
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# manifest / permissions / certificates honesty
# --------------------------------------------------------------------------
def test_manifest_maps_a_decode_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Axml:
        def get_xml(self) -> bytes:
            raise ValueError("corrupt AXML")

    class _Apk:
        def get_android_manifest_axml(self) -> _Axml:
            return _Axml()

        def get_package(self) -> str:
            return "com.example.app"

    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    with pytest.raises(ApkError) as caught:
        ApkClient().manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"


def test_permissions_falls_back_when_requested_is_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An androguard without get_requested_permissions reports declared for both."""

    class _Apk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET"]

        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("older androguard")

    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = ApkClient().permissions(tmp_path / "app.apk")
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["requested_permissions"] == ["android.permission.INTERNET"]


class _GoodCert:
    subject = "CN=Example"
    issuer = "CN=Example"
    serial_number = 12345
    sha256_fingerprint = "aabbcc"


class _BrokenCert:
    @property
    def subject(self) -> str:
        raise ValueError("certificate object from a different androguard")


def test_certificates_survives_a_signature_read_and_a_bad_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """get_signature_names raising leaves v1_signed false, and a cert that throws is skipped."""

    class _Apk:
        def get_signature_names(self) -> list[str]:
            raise RuntimeError("no v1 block")

        def get_certificates(self) -> list[Any]:
            return [_GoodCert(), _BrokenCert()]

    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = ApkClient().certificates(tmp_path / "app.apk")
    assert payload["v1_signed"] is False
    assert payload["signature_files"] == []
    # The good cert is kept; the one that raised on attribute access is dropped.
    assert len(payload["certificates"]) == 1
    assert payload["certificates"][0]["subject"] == "CN=Example"


# --------------------------------------------------------------------------
# native_libs / classes / methods / xrefs branch guards
# --------------------------------------------------------------------------
def test_native_libs_only_counts_an_abi_from_a_full_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Apk:
        def get_files(self) -> list[str]:
            # "lib/x.so" has no abi segment; "lib/arm64-v8a/libx.so" does.
            return ["lib/x.so", "lib/arm64-v8a/libx.so", "res/layout.xml"]

    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = ApkClient().native_libs(tmp_path / "app.apk")
    assert payload["native_libs"] == ["lib/arm64-v8a/libx.so", "lib/x.so"]
    assert payload["abis"] == ["arm64-v8a"]


class _FakeClass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _ClassParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def test_classes_skips_external_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    classes = [
        _FakeClass("Landroid/os/Bundle;", external=True),
        _FakeClass("Lcom/example/Foo;"),
    ]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _ClassParsed(classes))
    payload = ApkClient().classes(tmp_path / "app.apk")
    assert payload["classes"] == ["Lcom/example/Foo;"]


def test_methods_requires_a_class_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _ClassParsed([]))
    with pytest.raises(ApkError) as caught:
        ApkClient().methods(tmp_path / "app.apk", "   ")
    assert caught.value.code == "invalid_params"


def test_methods_reports_a_class_that_is_not_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _ClassParsed([_FakeClass("Lcom/example/Other;")]),
    )
    with pytest.raises(ApkError) as caught:
        ApkClient().methods(tmp_path / "app.apk", "com.example.Missing")
    assert caught.value.code == "not_found"


class _FakeXrefMethod:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[Any]:
        return []


class _XrefParsed:
    def __init__(self, methods: list[_FakeXrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeXrefMethod]:
        return self._methods


def test_xrefs_requires_a_method_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _XrefParsed([]))
    with pytest.raises(ApkError) as caught:
        ApkClient().xrefs(tmp_path / "app.apk", "")
    assert caught.value.code == "invalid_params"


def test_xrefs_skips_external_and_mismatched_methods(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    methods = [
        _FakeXrefMethod("decrypt", external=True),
        _FakeXrefMethod("unrelated"),
    ]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _XrefParsed(methods))
    payload = ApkClient().xrefs(tmp_path / "app.apk", "decrypt")
    assert payload["callers"] == []
    assert payload["has_more"] is False


def test_dotted_to_smali_leaves_a_smali_name_untouched() -> None:
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
