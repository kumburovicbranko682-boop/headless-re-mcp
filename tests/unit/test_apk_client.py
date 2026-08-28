"""Guards, helpers, and error/fallback branches of the androguard adapter.

The test_apk_*_fields.py files stub _apk/_parsed and pin each tool's happy-path
shape (and that its docstring names the real fields). What is left untested is
the logic those stubs skip past: the _require input guard that fronts every
call, the pure key/name helpers, and the defensive branches inside the tools --
the fallback when an older androguard lacks an accessor, tolerance of one
malformed certificate, the skip of imported (external) classes, and the
class/method-name guards. androguard is imported for real here (so `available`
is genuinely True), but no APK is ever parsed: _require is exercised with real
paths, and the tool bodies run against small fakes standing in for androguard's
duck-typed data model, the same way the field tests do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _cap_names,
    _dotted_to_smali,
)

# --- input guard and pure helpers ----------------------------------------


def test_require_reports_not_found_for_a_missing_apk(tmp_path: Path) -> None:
    client = ApkClient()
    with pytest.raises(ApkError) as caught:
        client._require(tmp_path / "nope.apk")
    assert caught.value.code == "not_found"
    assert caught.value.details["path"].endswith("nope.apk")


def test_require_degrades_when_androguard_is_absent(tmp_path: Path) -> None:
    # The install is present, so force the flag to model a host without it: the
    # backend must say capability_unavailable, not crash on a later import.
    client = ApkClient()
    client._available = False
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    with pytest.raises(ApkError) as caught:
        client._require(apk)
    assert caught.value.code == "capability_unavailable"


def test_require_returns_the_resolved_existing_path(tmp_path: Path) -> None:
    client = ApkClient()
    assert client.available is True
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    resolved = client._require(apk)
    assert resolved == apk.resolve()
    # _key pairs the resolved path with its mtime so a rebuilt APK misses cache.
    path_str, mtime = client._key(resolved)
    assert path_str == str(resolved)
    assert isinstance(mtime, int)


def test_cap_names_caps_in_iteration_order_then_sorts_the_page() -> None:
    # The cap is applied to the first `limit` items in iteration order, and only
    # that retained page is sorted -- so a capped result reflects androguard's
    # emission order, not a global sort. ["c","a","b"] cap 2 keeps "c","a".
    names, has_more = _cap_names(["c", "a", "b"], 2)
    assert names == ["a", "c"]
    assert has_more is True
    exact, exact_more = _cap_names(["b", "a"], 2)
    assert exact == ["a", "b"]
    assert exact_more is False
    empty, empty_more = _cap_names(None, 5)
    assert empty == []
    assert empty_more is False


def test_dotted_to_smali_converts_and_passes_smali_through() -> None:
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
    # Already smali: returned unchanged rather than double-wrapped.
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"


# --- fakes for the tool bodies -------------------------------------------


class _FakeAnalysis:
    def __init__(self, classes: Any = (), methods: Any = ()) -> None:
        self._classes = classes
        self._methods = methods

    def get_classes(self) -> Any:
        return self._classes

    def get_methods(self) -> Any:
        return self._methods


class _FakeParsed:
    def __init__(self, analysis: _FakeAnalysis) -> None:
        self.analysis = analysis


class _FakeKlass:
    def __init__(self, name: str, *, external: bool = False, methods: Any = ()) -> None:
        self.name = name
        self._external = external
        self._methods = methods

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> Any:
        return self._methods


class _FakeMethodEntry:
    def __init__(self, name: str) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"


class _FakeCall:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeXrefMethod:
    def __init__(self, name: str, *, external: bool = False, callers: Any = ()) -> None:
        self.name = name
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> Any:
        for call in self._callers:
            yield (None, call, 0)


def _with_parsed(client: ApkClient, analysis: _FakeAnalysis) -> None:
    client._parsed = lambda _path: _FakeParsed(analysis)  # type: ignore[method-assign]


# --- permissions / certificates fallbacks --------------------------------


def test_permissions_falls_back_when_androguard_lacks_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _OldApk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET"]

        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("older androguard has no get_requested_permissions")

    client = ApkClient()
    client._apk = lambda _path: _OldApk()  # type: ignore[method-assign]
    data = client.permissions(Path("dummy.apk"))
    assert data["permissions"] == ["android.permission.INTERNET"]
    # Falls back to the declared list rather than surfacing the AttributeError.
    assert data["requested_permissions"] == ["android.permission.INTERNET"]


def test_certificates_tolerates_missing_names_and_a_bad_cert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _GoodCert:
        subject = "CN=Good"
        issuer = "CN=Issuer"
        serial_number = 42
        sha256_fingerprint = "aa:bb"

    class _BadCert:
        subject = "CN=Bad"
        issuer = "CN=Issuer"
        serial_number = 7

        @property
        def sha256_fingerprint(self) -> str:
            # hasattr() only swallows AttributeError, so this non-attribute
            # error escapes into the per-cert guard and drops just this cert.
            raise ValueError("unreadable fingerprint")

    class _NoNamesApk:
        def get_signature_names(self) -> list[str]:
            raise RuntimeError("no v1 block")

        def get_certificates(self) -> list[Any]:
            return [_GoodCert(), _BadCert()]

    client = ApkClient()
    client._apk = lambda _path: _NoNamesApk()  # type: ignore[method-assign]
    data = client.certificates(Path("dummy.apk"))
    assert data["signature_files"] == []
    assert data["v1_signed"] is False
    assert len(data["certificates"]) == 1
    assert data["certificates"][0]["subject"] == "CN=Good"
    assert data["has_more"] is False


# --- classes / methods / xrefs branches ----------------------------------


def test_classes_skips_external_imported_classes() -> None:
    client = ApkClient()
    _with_parsed(
        client,
        _FakeAnalysis(
            classes=[
                _FakeKlass("Landroid/os/Bundle;", external=True),
                _FakeKlass("Lcom/example/App;"),
            ]
        ),
    )
    data = client.classes(Path("dummy.apk"))
    assert data["classes"] == ["Lcom/example/App;"]
    assert data["total"] == 1


def test_native_libs_lists_libs_and_derives_abis_only_from_full_paths() -> None:
    class _FilesApk:
        def get_files(self) -> list[str]:
            return [
                "lib/arm64-v8a/libfoo.so",
                "lib/short.so",  # under lib/ but no abi segment
                "res/layout/main.xml",  # not under lib/
            ]

    client = ApkClient()
    client._apk = lambda _path: _FilesApk()  # type: ignore[method-assign]
    data = client.native_libs(Path("dummy.apk"))
    assert data["native_libs"] == ["lib/arm64-v8a/libfoo.so", "lib/short.so"]
    # Only the three-segment path yields an abi; the bare lib/short.so does not.
    assert data["abis"] == ["arm64-v8a"]
    assert data["count"] == 2
    assert data["has_more"] is False


def test_methods_requires_a_class_name() -> None:
    client = ApkClient()
    _with_parsed(client, _FakeAnalysis())
    with pytest.raises(ApkError) as caught:
        client.methods(Path("dummy.apk"), "   ")
    assert caught.value.code == "invalid_params"


def test_methods_reports_not_found_for_an_absent_class() -> None:
    client = ApkClient()
    _with_parsed(client, _FakeAnalysis(classes=[_FakeKlass("Lcom/example/App;")]))
    with pytest.raises(ApkError) as caught:
        client.methods(Path("dummy.apk"), "com.example.Missing")
    assert caught.value.code == "not_found"
    assert caught.value.details["class_name"] == "com.example.Missing"


def test_methods_resolves_a_dotted_name_to_its_smali_class() -> None:
    client = ApkClient()
    klass = _FakeKlass(
        "Lcom/example/App;",
        methods=[_FakeMethodEntry("onCreate"), _FakeMethodEntry("onResume")],
    )
    _with_parsed(client, _FakeAnalysis(classes=[klass]))
    # Caller passes the dotted form; the client matches it to the smali name.
    data = client.methods(Path("dummy.apk"), "com.example.App", offset=1, limit=5)
    assert data["class_name"] == "Lcom/example/App;"
    assert data["total"] == 2
    assert data["count"] == 1
    assert data["methods"][0]["name"] == "onResume"
    assert data["has_more"] is False


def test_xrefs_requires_a_method_name() -> None:
    client = ApkClient()
    _with_parsed(client, _FakeAnalysis())
    with pytest.raises(ApkError) as caught:
        client.xrefs(Path("dummy.apk"), "  ")
    assert caught.value.code == "invalid_params"


def test_xrefs_filters_by_name_and_skips_external_then_caps() -> None:
    client = ApkClient()
    target = _FakeXrefMethod(
        "doWork",
        callers=[
            _FakeCall("Lcom/a;", "m1"),
            _FakeCall("Lcom/b;", "m2"),
            _FakeCall("Lcom/c;", "m3"),
        ],
    )
    methods = [
        _FakeXrefMethod("doWork", external=True, callers=[_FakeCall("Lz;", "zz")]),
        _FakeXrefMethod("other", callers=[_FakeCall("Ly;", "yy")]),
        target,
    ]
    _with_parsed(client, _FakeAnalysis(methods=methods))
    data = client.xrefs(Path("dummy.apk"), "doWork", limit=2)
    assert data["method_name"] == "doWork"
    # External same-named method and the differently-named one are both skipped;
    # only the internal target's callers count, capped at the limit.
    assert data["count"] == 2
    assert data["has_more"] is True
    assert {caller["class"] for caller in data["callers"]} == {"Lcom/a;", "Lcom/b;"}


def test_xrefs_reports_complete_when_under_the_cap() -> None:
    client = ApkClient()
    target = _FakeXrefMethod("doWork", callers=[_FakeCall("Lcom/a;", "m1")])
    _with_parsed(client, _FakeAnalysis(methods=[target]))
    data = client.xrefs(Path("dummy.apk"), "doWork", limit=100)
    assert data["count"] == 1
    assert data["has_more"] is False
