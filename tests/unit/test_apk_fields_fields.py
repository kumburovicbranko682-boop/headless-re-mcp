"""Field-level tests for ApkClient.fields (the class field lister).

Like the method_bytecode tests, these drive resolution and shaping with
lightweight fakes standing in for androguard's analysis objects, so the test
runs whether or not androguard is installed: ``fields`` reaches the DEX only
through ``_parsed``, which is monkeypatched here. The live end-to-end proof (a
real DEX with a field, read through the service) lives in the APK field gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


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
    def __init__(self, name: str, encoded: _FakeEncodedField) -> None:
        self.name = name
        self._encoded = encoded

    def get_field(self) -> _FakeEncodedField:
        return self._encoded


class _FakeClass:
    def __init__(self, name: str, fields: list[_FakeFieldAnalysis]) -> None:
        self.name = name
        self._fields = fields

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


def _store_class() -> _FakeClass:
    return _FakeClass(
        "Lcom/example/Store;",
        [
            _FakeFieldAnalysis("secret", _FakeEncodedField("secret", "I", "public static")),
            _FakeFieldAnalysis(
                "name",
                _FakeEncodedField("name", "Ljava/lang/String;", "private"),
            ),
        ],
    )


def test_lists_fields_with_type_and_access(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_store_class()], monkeypatch)

    # Dotted class form resolves to the Lsmali/ form class.
    data = client.fields(_APK, "com.example.Store")

    assert data["class_name"] == "Lcom/example/Store;"
    assert data["total"] == 2
    assert data["count"] == 2
    assert data["has_more"] is False
    assert data["scan_capped"] is False
    by_name = {f["name"]: f for f in data["fields"]}
    assert by_name["secret"]["type"] == "I"
    assert by_name["secret"]["access"] == "public static"
    # A String field keeps its raw Dalvik type descriptor.
    assert by_name["name"]["type"] == "Ljava/lang/String;"
    assert by_name["name"]["access"] == "private"


def test_smali_form_resolves_too(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_store_class()], monkeypatch)
    data = client.fields(_APK, "Lcom/example/Store;")
    assert data["class_name"] == "Lcom/example/Store;"
    assert data["total"] == 2


def test_paginates_with_offset_and_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_store_class()], monkeypatch)
    page = client.fields(_APK, "com.example.Store", offset=1, limit=1)
    assert page["offset"] == 1
    assert page["count"] == 1
    assert page["total"] == 2
    assert page["has_more"] is False


def test_class_with_no_fields_is_a_clean_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_FakeClass("Lcom/example/Empty;", [])], monkeypatch)
    data = client.fields(_APK, "com.example.Empty")
    assert data["fields"] == []
    assert data["total"] == 0
    assert data["count"] == 0
    assert data["has_more"] is False


def test_missing_class_and_blank_are_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_store_class()], monkeypatch)

    with pytest.raises(ApkError) as no_class:
        client.fields(_APK, "com.example.Absent")
    assert no_class.value.code == "not_found"

    with pytest.raises(ApkError) as blank:
        client.fields(_APK, "   ")
    assert blank.value.code == "invalid_params"


def test_docstring_names_the_fields_agents_read() -> None:
    doc = ApkClient.fields.__doc__ or ""
    for token in ("type", "access", "field_xrefs"):
        assert token in doc, token
