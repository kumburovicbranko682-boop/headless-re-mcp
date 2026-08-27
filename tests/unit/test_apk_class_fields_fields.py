"""apk.class_fields lists a class's declared fields via ClassAnalysis.get_fields.

The fake parsed APK stands in for androguard's get_classes and each
ClassAnalysis.get_fields()/FieldAnalysis.get_field()/EncodedField accessors,
matching the real 4.x shape, so name resolution, the name/descriptor/access
extraction, bounding, pagination and the not-found path get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_METHODS_COLLECT,
    ApkClient,
    ApkError,
)
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


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
        self._encoded = encoded

    def get_field(self) -> _FakeEncodedField:
        return self._encoded


class _FakeClass:
    def __init__(self, name: str, fields: list[_FakeEncodedField]) -> None:
        self.name = name
        self._fields = [_FakeFieldAnalysis(f) for f in fields]

    def get_fields(self) -> list[_FakeFieldAnalysis]:
        return self._fields


class _FakeParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def _client(classes: list[_FakeClass]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(classes)  # type: ignore[method-assign]
    return client


def test_lists_fields_with_descriptor_and_access() -> None:
    """Each field's name, type descriptor and access-flag string come through.

    Measured: a dotted class name resolves to the smali class, and the rows
    carry descriptor (the type) and access as reported by androguard.
    """
    klass = _FakeClass(
        "Lcom/example/Config;",
        [
            _FakeEncodedField("API_KEY", "Ljava/lang/String;", "public static final"),
            _FakeEncodedField("count", "I", "private"),
        ],
    )
    payload = _client([klass]).class_fields(Path("dummy.apk"), "com.example.Config")
    assert payload["class_name"] == "Lcom/example/Config;"
    assert payload["fields"] == [
        {"name": "API_KEY", "descriptor": "Ljava/lang/String;", "access": "public static final"},
        {"name": "count", "descriptor": "I", "access": "private"},
    ]
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_accepts_smali_form_class_name() -> None:
    """The Lsmali/form is accepted directly, not only the dotted name."""
    klass = _FakeClass("Lcom/example/Foo;", [_FakeEncodedField("x", "I", "public")])
    payload = _client([klass]).class_fields(Path("dummy.apk"), "Lcom/example/Foo;")
    assert payload["total"] == 1


def test_paginates() -> None:
    """A full page reports has_more with a stable window in declaration order."""
    fields = [_FakeEncodedField(f"f{i:03d}", "I", "private") for i in range(25)]
    client = _client([_FakeClass("La;", fields)])
    first = client.class_fields(Path("dummy.apk"), "La;", offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    assert first["fields"][0]["name"] == "f000"
    second = client.class_fields(Path("dummy.apk"), "La;", offset=10, limit=10)
    assert second["offset"] == 10
    assert second["fields"][0]["name"] == "f010"


def test_scan_capped_over_collection_ceiling() -> None:
    """More fields than the collection ceiling sets scan_capped."""
    fields = [
        _FakeEncodedField(f"f{i:05d}", "I", "public")
        for i in range(_MAX_METHODS_COLLECT + 20)
    ]
    payload = _client([_FakeClass("La;", fields)]).class_fields(
        Path("dummy.apk"), "La;", limit=1000
    )
    assert payload["total"] == _MAX_METHODS_COLLECT
    assert payload["scan_capped"] is True


def test_class_not_found_raises() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client([_FakeClass("La;", [])]).class_fields(Path("dummy.apk"), "com.missing.X")
    assert excinfo.value.code == "not_found"


def test_requires_a_class_name() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client([_FakeClass("La;", [])]).class_fields(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_class_fields_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.class_fields")
    assert "Answers with" in doc
    assert "descriptor" in doc
    assert "scan_capped" in doc
