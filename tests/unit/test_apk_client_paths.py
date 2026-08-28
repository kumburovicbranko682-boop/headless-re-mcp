"""The APK client's parse/cache layer and its per-method error branches.

The apk *_fields tests monkeypatch ``_apk`` / ``_parsed`` to bypass parsing, so
the availability gate, the light/full parse-and-cache paths, ``release`` and a
handful of version-tolerant ``except`` arms never run. androguard is optional
and not installed here, so a fake ``androguard`` package tree is injected to
drive the real parse/cache code; the error-branch tests keep monkeypatching the
parse seams the way the existing suite does.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.apk.client import (
    _CACHE_LIMIT,
    ApkClient,
    ApkError,
    _dotted_to_smali,
)


@pytest.fixture
def fake_androguard(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    """Inject a fake androguard package so the client reports itself available.

    Each test assigns ``core_apk.APK`` / ``misc.AnalyzeAPK`` to control what the
    lazy imports inside ``_apk`` / ``_parsed`` resolve to.
    """
    androguard = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    core_apk = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    core.apk = core_apk  # type: ignore[attr-defined]
    androguard.core = core  # type: ignore[attr-defined]
    androguard.misc = misc  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "androguard", androguard)
    monkeypatch.setitem(sys.modules, "androguard.core", core)
    monkeypatch.setitem(sys.modules, "androguard.core.apk", core_apk)
    monkeypatch.setitem(sys.modules, "androguard.misc", misc)
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    try:
        yield SimpleNamespace(core_apk=core_apk, misc=misc)
    finally:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()


def _apk_file(tmp_path: Path, name: str = "app.apk") -> Path:
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04 fake apk bytes")
    return path


# --- availability + require -----------------------------------------------------


def test_without_androguard_the_client_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force the lazy ``import androguard`` to fail so the unavailable path runs
    # whether or not androguard is installed. The android extra is a documented,
    # supported configuration, so this test must not assume its absence.
    monkeypatch.setitem(sys.modules, "androguard", None)
    client = ApkClient()

    assert client.available is False
    with pytest.raises(ApkError) as caught:
        client._require(_apk_file(tmp_path))
    assert caught.value.code == "capability_unavailable"


def test_available_client_rejects_a_missing_file(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    client = ApkClient()

    assert client.available is True
    with pytest.raises(ApkError) as caught:
        client._require(tmp_path / "nope.apk")
    assert caught.value.code == "not_found"


# --- light parse + cache --------------------------------------------------------


def test_light_parse_is_cached_per_path(tmp_path: Path, fake_androguard: SimpleNamespace) -> None:
    built: list[str] = []

    class FakeAPK:
        def __init__(self, path: str) -> None:
            built.append(path)

    fake_androguard.core_apk.APK = FakeAPK
    client = ApkClient()
    apk_path = _apk_file(tmp_path)

    first = client._apk(apk_path)
    second = client._apk(apk_path)  # cache hit -> move_to_end, no re-parse

    assert first is second
    assert len(built) == 1


def test_a_light_parse_failure_becomes_a_backend_error(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    class BoomAPK:
        def __init__(self, path: str) -> None:
            raise ValueError("not a zip")

    fake_androguard.core_apk.APK = BoomAPK
    client = ApkClient()

    with pytest.raises(ApkError) as caught:
        client._apk(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"
    assert "failed to parse APK" in caught.value.message


def test_the_light_cache_evicts_the_oldest_entry(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    class FakeAPK:
        def __init__(self, path: str) -> None:
            self.path = path

    fake_androguard.core_apk.APK = FakeAPK
    client = ApkClient()
    paths = [_apk_file(tmp_path, f"app{i}.apk") for i in range(_CACHE_LIMIT + 1)]
    for path in paths:
        client._apk(path)

    assert len(ApkClient._light_cache) == _CACHE_LIMIT
    resolved_first = str(paths[0].resolve())
    assert all(key[0] != resolved_first for key in ApkClient._light_cache)


# --- full parse + cache ---------------------------------------------------------


def test_full_parse_builds_and_caches_the_analysis(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    built: list[str] = []

    def analyze(path: str) -> tuple[object, object, object]:
        built.append(path)
        return (object(), object(), object())

    fake_androguard.misc.AnalyzeAPK = analyze
    client = ApkClient()
    apk_path = _apk_file(tmp_path)

    first = client._parsed(apk_path)
    second = client._parsed(apk_path)

    assert first is second
    assert len(built) == 1
    assert first.apk is not None and first.analysis is not None


def test_a_full_parse_failure_becomes_a_backend_error(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    def boom(path: str) -> tuple[object, object, object]:
        raise RuntimeError("dex exploded")

    fake_androguard.misc.AnalyzeAPK = boom
    client = ApkClient()

    with pytest.raises(ApkError) as caught:
        client._parsed(_apk_file(tmp_path))
    assert caught.value.code == "backend_error"
    assert "failed to analyze APK" in caught.value.message


def test_the_full_cache_evicts_the_oldest_entry(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    fake_androguard.misc.AnalyzeAPK = lambda path: (object(), object(), object())
    client = ApkClient()
    for i in range(_CACHE_LIMIT + 1):
        client._parsed(_apk_file(tmp_path, f"full{i}.apk"))

    assert len(ApkClient._full_cache) == _CACHE_LIMIT


# --- release --------------------------------------------------------------------


def test_release_drops_every_cached_parse_for_a_path(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    fake_androguard.core_apk.APK = lambda path: SimpleNamespace(path=path)
    fake_androguard.misc.AnalyzeAPK = lambda path: (object(), object(), object())
    client = ApkClient()
    apk_path = _apk_file(tmp_path)
    client._apk(apk_path)
    client._parsed(apk_path)

    assert ApkClient.release(apk_path) is True
    assert not ApkClient._light_cache
    assert not ApkClient._full_cache


def test_release_of_an_uncached_path_reports_nothing_dropped(
    tmp_path: Path, fake_androguard: SimpleNamespace
) -> None:
    assert ApkClient.release(tmp_path / "never-parsed.apk") is False


def test_release_swallows_a_resolve_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom_resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        raise OSError("path resolution failed")

    monkeypatch.setattr(Path, "resolve", boom_resolve)

    assert ApkClient.release(tmp_path / "app.apk") is False


# --- per-method error branches (parse seams monkeypatched) ----------------------


def test_manifest_decode_failure_is_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BadManifest:
        def get_android_manifest_axml(self) -> Any:
            raise RuntimeError("axml is corrupt")

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: BadManifest())

    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"
    assert "failed to decode manifest" in caught.value.message


def test_permissions_falls_back_when_requested_is_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class OldApk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET", "android.permission.CAMERA"]

        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("older androguard has no requested permissions")

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: OldApk())

    payload = client.permissions(tmp_path / "app.apk")

    assert payload["requested_permissions"] == payload["permissions"]
    assert payload["count"] == 2


def test_certificates_tolerate_missing_signatures_and_odd_certs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class GoodCert:
        subject = "CN=Good"
        issuer = "CN=Issuer"
        serial_number = 12345
        sha256_fingerprint = "abcd"

    class ExplodingCert:
        @property
        def subject(self) -> str:
            raise RuntimeError("this certificate object is from another version")

    class WeirdApk:
        def get_signature_names(self) -> list[str]:
            raise RuntimeError("v1 signature block unreadable")

        def get_certificates(self) -> list[object]:
            return [GoodCert(), ExplodingCert()]

    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: WeirdApk())

    payload = client.certificates(tmp_path / "app.apk")

    assert payload["signature_files"] == []
    assert payload["v1_signed"] is False
    assert len(payload["certificates"]) == 1  # the exploding cert was skipped
    assert payload["certificates"][0]["subject"] == "CN=Good"


class _FakeClass:
    def __init__(self, name: str, *, external: bool) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _ClassAnalysis:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def test_classes_skips_external_classes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parsed = _ClassAnalysis(
        [
            _FakeClass("Lcom/app/Internal;", external=False),
            _FakeClass("Landroid/os/Bundle;", external=True),
        ]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    payload = client.classes(tmp_path / "app.apk")

    assert payload["classes"] == ["Lcom/app/Internal;"]
    assert payload["total"] == 1


def test_methods_requires_a_class_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _ClassAnalysis([]))

    with pytest.raises(ApkError) as caught:
        client.methods(tmp_path / "app.apk", "   ")
    assert caught.value.code == "invalid_params"


def test_methods_reports_an_unknown_class(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parsed = _ClassAnalysis([_FakeClass("Lcom/app/Other;", external=False)])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    with pytest.raises(ApkError) as caught:
        client.methods(tmp_path / "app.apk", "com.app.Missing")
    assert caught.value.code == "not_found"


class _XrefMethod:
    def __init__(self, name: str, *, external: bool) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, object, int]]:
        call = SimpleNamespace(class_name="Lcom/app/Caller;", name="run")
        return [(None, call, 0)]


class _XrefAnalysis:
    def __init__(self, methods: list[_XrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_XrefMethod]:
        return self._methods


def test_xrefs_requires_a_method_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _XrefAnalysis([]))

    with pytest.raises(ApkError) as caught:
        client.xrefs(tmp_path / "app.apk", "  ")
    assert caught.value.code == "invalid_params"


def test_xrefs_ignore_external_and_mismatched_methods(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _XrefAnalysis(
        [
            _XrefMethod("decrypt", external=True),  # skipped: external
            _XrefMethod("other", external=False),  # skipped: wrong name
            _XrefMethod("decrypt", external=False),  # the real match
        ]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    payload = client.xrefs(tmp_path / "app.apk", "decrypt")

    assert payload["count"] == 1
    assert payload["callers"][0]["class"] == "Lcom/app/Caller;"


def test_dotted_to_smali_leaves_smali_form_untouched() -> None:
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"


# --- scan-cap ("collected too many") branches -----------------------------------


def test_classes_report_when_the_scan_hit_the_collect_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import headless_re_mcp.backends.apk.client as apk_client

    monkeypatch.setattr(apk_client, "_MAX_CLASSES_COLLECT", 1)
    parsed = _ClassAnalysis(
        [
            _FakeClass("Lcom/app/A;", external=False),
            _FakeClass("Lcom/app/B;", external=False),
        ]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    payload = client.classes(tmp_path / "app.apk")

    assert payload["scan_capped"] is True
    assert payload["total"] == 1


class _MethodClass:
    def __init__(self, name: str, method_names: list[str]) -> None:
        self.name = name
        self._methods = [
            SimpleNamespace(name=m, descriptor="()V", access="public") for m in method_names
        ]

    def get_methods(self) -> list[Any]:
        return self._methods


def test_methods_report_when_the_scan_hit_the_collect_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import headless_re_mcp.backends.apk.client as apk_client

    monkeypatch.setattr(apk_client, "_MAX_METHODS_COLLECT", 1)
    parsed = _ClassAnalysis([])  # only needs get_classes
    parsed._classes = cast(Any, [_MethodClass("Lcom/app/A;", ["one", "two"])])
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)

    payload = client.methods(tmp_path / "app.apk", "Lcom/app/A;")

    assert payload["scan_capped"] is True
    assert payload["total"] == 1


class _StringItem:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _StringAnalysis:
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = [_StringItem(v) for v in values]

    def get_strings(self) -> list[_StringItem]:
        return self._values


def test_strings_report_when_the_scan_hit_the_collect_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import headless_re_mcp.backends.apk.client as apk_client

    monkeypatch.setattr(apk_client, "_MAX_STRINGS_COLLECT", 1)
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _StringAnalysis(["alpha", "beta"]))

    payload = client.strings(tmp_path / "app.apk")

    assert payload["scan_capped"] is True
    assert payload["total"] == 1


class _NativeLibApk:
    def __init__(self, files: list[str]) -> None:
        self._files = files

    def get_files(self) -> list[str]:
        return self._files


def test_native_libs_ignore_lib_paths_without_an_abi_segment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apk = _NativeLibApk(
        [
            "lib/arm64-v8a/libnative.so",  # full abi path
            "lib/toplevel.so",  # only two parts -> no abi segment
            "res/layout/main.xml",  # not a lib
        ]
    )
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)

    payload = client.native_libs(tmp_path / "app.apk")

    assert payload["abis"] == ["arm64-v8a"]
    assert payload["native_libs"] == ["lib/arm64-v8a/libnative.so", "lib/toplevel.so"]
    assert payload["has_more"] is False
