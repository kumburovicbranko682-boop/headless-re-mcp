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

Everything runs against injected fakes -- androguard is never really invoked,
and the CI quality job (which installs only ``.[test,dev,web]``) sees the same
behaviour as a checkout that has the ``android`` extra.
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
    finder entirely, so these cache tests behave the same either way.
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
    _fake_androguard(monkeypatch)
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
def _client_with_apk(monkeypatch: pytest.MonkeyPatch, apk_obj: Any) -> ApkClient:
    """A client whose _apk returns a fixed fake, bypassing parse+cache."""
    _fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk_obj)
    return client


def _client_with_parsed(monkeypatch: pytest.MonkeyPatch, analysis: Any) -> ApkClient:
    _fake_androguard(monkeypatch)
    client = ApkClient()
    client._available = True
    parsed = _ParsedApk(object(), analysis, object())
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    return client


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
            return "com.example"

    client = _client_with_apk(monkeypatch, _Apk())
    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"


def test_permissions_falls_back_when_requested_is_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Apk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET"]

        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("older androguard")

    client = _client_with_apk(monkeypatch, _Apk())
    payload = client.permissions(tmp_path / "app.apk")
    # The declared list stands in for requested when the newer call is absent.
    assert payload["requested_permissions"] == ["android.permission.INTERNET"]


def test_certificates_survive_a_signature_name_error_and_bad_cert_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _GoodCert:
        subject = "CN=Good"
        issuer = "CN=CA"
        serial_number = 7
        sha256_fingerprint = "abcd"

    class _ExplodingCert:
        @property
        def subject(self) -> str:
            raise RuntimeError("unreadable cert")

    class _Apk:
        def get_signature_names(self) -> list[str]:
            raise RuntimeError("no v1 block")

        def get_certificates(self) -> list[Any]:
            return [_GoodCert(), _ExplodingCert()]

    client = _client_with_apk(monkeypatch, _Apk())
    payload = client.certificates(tmp_path / "app.apk")
    # The signature-name error degrades to an empty list; the good cert survives,
    # the exploding one is skipped rather than crashing the call.
    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False
    assert len(payload["certificates"]) == 1
    assert payload["certificates"][0]["subject"] == "CN=Good"


def test_native_libs_reads_abis_from_lib_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Apk:
        def get_files(self) -> list[str]:
            return [
                "lib/arm64-v8a/libfoo.so",
                "lib/x86/libbar.so",
                "lib/onlytwo",  # too short to name an ABI
                "res/layout.xml",  # not a native lib
            ]

    client = _client_with_apk(monkeypatch, _Apk())
    payload = client.native_libs(tmp_path / "app.apk")
    assert payload["abis"] == ["arm64-v8a", "x86"]
    assert "lib/arm64-v8a/libfoo.so" in payload["native_libs"]
    assert payload["count"] == 3


# --------------------------------------------------------------------------
# classes / methods / xrefs guards
# --------------------------------------------------------------------------
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


def test_classes_skips_external_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analysis:
        def get_classes(self) -> list[_Klass]:
            return [
                _Klass("Lcom/app/A;"),
                _Klass("Landroid/os/Bundle;", external=True),
                _Klass("Lcom/app/B;"),
            ]

    client = _client_with_parsed(monkeypatch, _Analysis())
    payload = client.classes(tmp_path / "app.apk")
    assert payload["classes"] == ["Lcom/app/A;", "Lcom/app/B;"]
    assert payload["total"] == 2


def test_methods_require_a_class_name_and_report_a_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Analysis:
        def get_classes(self) -> list[_Klass]:
            return [_Klass("Lcom/app/A;")]

    client = _client_with_parsed(monkeypatch, _Analysis())
    with pytest.raises(ApkError) as blank:
        client.methods(tmp_path / "app.apk", "   ")
    assert blank.value.code == "invalid_params"
    with pytest.raises(ApkError) as missing:
        client.methods(tmp_path / "app.apk", "com.app.Nope")
    assert missing.value.code == "not_found"


def test_methods_resolve_a_dotted_class_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    method = types.SimpleNamespace(name="decrypt", descriptor="()V", access="public")

    class _Analysis:
        def get_classes(self) -> list[_Klass]:
            return [_Klass("Lcom/app/A;", methods=[method])]

    client = _client_with_parsed(monkeypatch, _Analysis())
    # The dotted form is converted to smali and still resolves the class.
    payload = client.methods(tmp_path / "app.apk", "com.app.A")
    assert payload["class_name"] == "Lcom/app/A;"
    assert payload["methods"][0]["name"] == "decrypt"


def test_xrefs_require_a_method_name_and_skip_non_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caller = types.SimpleNamespace(class_name="Lcom/app/Caller;", name="invoke")
    match = types.SimpleNamespace(
        name="decrypt",
        is_external=lambda: False,
        get_xref_from=lambda: [(None, caller, 0)],
    )
    external = types.SimpleNamespace(
        name="decrypt", is_external=lambda: True, get_xref_from=lambda: []
    )
    other = types.SimpleNamespace(
        name="unrelated", is_external=lambda: False, get_xref_from=lambda: []
    )

    class _Analysis:
        def get_methods(self) -> list[Any]:
            return [external, other, match]

    client = _client_with_parsed(monkeypatch, _Analysis())
    with pytest.raises(ApkError) as blank:
        client.xrefs(tmp_path / "app.apk", "  ")
    assert blank.value.code == "invalid_params"

    payload = client.xrefs(tmp_path / "app.apk", "decrypt")
    assert payload["count"] == 1
    assert payload["callers"][0]["class"] == "Lcom/app/Caller;"


# --------------------------------------------------------------------------
# _dotted_to_smali
# --------------------------------------------------------------------------
def test_dotted_to_smali_leaves_an_existing_smali_name() -> None:
    assert _dotted_to_smali("Lcom/app/A;") == "Lcom/app/A;"
    assert _dotted_to_smali("com.app.A") == "Lcom/app/A;"
