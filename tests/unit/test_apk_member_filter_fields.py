"""Filter behaviour for apk.methods and apk.fields (name_contains / access).

Driven with lightweight fakes for androguard's analysis objects, so the test
runs whether or not androguard is installed: both listers reach the DEX only
through ``_parsed``, monkeypatched here. The live proof over real DEX fixtures
lives in the APK integration gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient


class _FakeMethod:
    def __init__(self, name: str, descriptor: str, access: str) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access


class _FakeEncodedField:
    def __init__(self, name: str, descriptor: str, access: str) -> None:
        self._name = name
        self._descriptor = descriptor
        self._access = access

    def get_name(self) -> str:
        return self._name

    def get_descriptor(self) -> str:
        return self._descriptor

    def get_access_flags_string(self) -> str:
        return self._access


class _FakeFieldAnalysis:
    def __init__(self, encoded: _FakeEncodedField) -> None:
        self.name = encoded.get_name()
        self._encoded = encoded

    def get_field(self) -> _FakeEncodedField:
        return self._encoded


class _FakeClass:
    def __init__(
        self,
        name: str,
        methods: list[_FakeMethod] | None = None,
        fields: list[_FakeFieldAnalysis] | None = None,
    ) -> None:
        self.name = name
        self._methods = methods or []
        self._fields = fields or []

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods

    def get_fields(self) -> list[_FakeFieldAnalysis]:
        return self._fields


class _FakeAnalysis:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


class _FakeParsed:
    def __init__(self, analysis: _FakeAnalysis) -> None:
        self.analysis = analysis


def _client_with(classes: list[_FakeClass], monkeypatch: pytest.MonkeyPatch) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(client, "_parsed", lambda _path: _FakeParsed(_FakeAnalysis(classes)))
    return client


_APK = Path("/nonexistent/app.apk")


def _app_class() -> _FakeClass:
    return _FakeClass(
        "Lcom/example/App;",
        methods=[
            _FakeMethod("main", "()V", "public static"),
            _FakeMethod("onCreate", "()V", "public static"),
            _FakeMethod("doWork", "()V", "private"),
            _FakeMethod("nativeInit", "()V", "public native"),
        ],
    )


def _names(payload: dict) -> list[str]:
    return sorted(m["name"] for m in payload["methods"])


def test_methods_filter_by_name_and_access(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_app_class()], monkeypatch)

    # No filter: all four, no filter key echoed.
    plain = client.methods(_APK, "com.example.App")
    assert plain["total"] == 4
    assert "filter" not in plain

    # Name substring, case-insensitive.
    assert _names(client.methods(_APK, "com.example.App", name_contains="Create")) == ["onCreate"]
    assert _names(client.methods(_APK, "com.example.App", name_contains="INIT")) == ["nativeInit"]

    # access="native" is the JNI-bridge triage move.
    native = client.methods(_APK, "com.example.App", access="native")
    assert _names(native) == ["nativeInit"]
    assert native["total"] == 1
    assert native["filter"] == {"access": "native"}

    assert _names(client.methods(_APK, "com.example.App", access="private")) == ["doWork"]
    assert _names(client.methods(_APK, "com.example.App", access="static")) == ["main", "onCreate"]

    # Filters combine with AND, and the echoed filter is normalised to lower case.
    combined = client.methods(_APK, "com.example.App", name_contains="o", access="private")
    assert _names(combined) == ["doWork"]
    assert combined["filter"] == {"name_contains": "o", "access": "private"}

    # A filter that matches nothing is a clean empty page, not the whole class.
    none = client.methods(_APK, "com.example.App", access="protected")
    assert none["total"] == 0
    assert none["methods"] == []


def test_methods_filter_paginates_over_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_app_class()], monkeypatch)
    first = client.methods(_APK, "com.example.App", access="static", limit=1, offset=0)
    assert first["total"] == 2
    assert first["count"] == 1
    assert first["has_more"] is True
    second = client.methods(_APK, "com.example.App", access="static", limit=1, offset=1)
    assert second["count"] == 1
    assert second["has_more"] is False


def _store_class() -> _FakeClass:
    return _FakeClass(
        "Lcom/example/Store;",
        fields=[
            _FakeFieldAnalysis(_FakeEncodedField("secret", "I", "public static")),
            _FakeFieldAnalysis(_FakeEncodedField("name", "Ljava/lang/String;", "private")),
            _FakeFieldAnalysis(
                _FakeEncodedField("TAG", "Ljava/lang/String;", "private static final")
            ),
        ],
    )


def _field_names(payload: dict) -> list[str]:
    return sorted(f["name"] for f in payload["fields"])


def test_fields_filter_by_name_and_access(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_store_class()], monkeypatch)

    plain = client.fields(_APK, "com.example.Store")
    assert plain["total"] == 3
    assert "filter" not in plain

    assert _field_names(client.fields(_APK, "com.example.Store", name_contains="secret")) == [
        "secret"
    ]
    assert _field_names(client.fields(_APK, "com.example.Store", access="static")) == [
        "TAG",
        "secret",
    ]
    finals = client.fields(_APK, "com.example.Store", access="final")
    assert _field_names(finals) == ["TAG"]
    assert finals["filter"] == {"access": "final"}


def test_filter_docstrings_name_the_fields() -> None:
    for doc in (ApkClient.methods.__doc__ or "", ApkClient.fields.__doc__ or ""):
        assert "name_contains" in doc
        assert "access" in doc
