"""apk.class_info reports one class's shape (super/interfaces/access/fields).

These mock the parsed analysis so the shaping is pinned without a DEX: the full
field set, dotted-name resolution, the not_found and invalid_params errors, the
field cap, and the docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import _MAX_FIELDS, ApkClient, ApkError
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


class _FakeField:
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


class _FakeVmClass:
    def __init__(self, access: str, fields: list[_FakeField]) -> None:
        self._access = access
        self._fields = fields

    def get_access_flags_string(self) -> str:
        return self._access

    def get_fields(self) -> list[_FakeField]:
        return self._fields


class _FakeMethod:
    def is_external(self) -> bool:
        return False


class _FakeClassAnalysis:
    def __init__(
        self,
        name: str,
        *,
        extends: str = "Ljava/lang/Object;",
        implements: list[str] | None = None,
        access: str = "public",
        fields: list[_FakeField] | None = None,
        methods: int = 1,
        external: bool = False,
    ) -> None:
        self.name = name
        self.extends = extends
        self.implements = implements or []
        self._access = access
        self._fields = fields or []
        self._methods = [_FakeMethod() for _ in range(methods)]
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_vm_class(self) -> _FakeVmClass:
        return _FakeVmClass(self._access, self._fields)

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeParsed:
    def __init__(self, classes: list[_FakeClassAnalysis]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClassAnalysis]:
        return self._classes


def _patch(monkeypatch: Any, classes: list[_FakeClassAnalysis]) -> ApkClient:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(classes))
    return ApkClient()


def test_apk_class_info_reports_the_full_shape(tmp_path: Path, monkeypatch: Any) -> None:
    klass = _FakeClassAnalysis(
        "Lcom/example/Pinner;",
        extends="Landroid/app/Activity;",
        implements=["Ljavax/net/ssl/X509TrustManager;", "Ljava/lang/Runnable;"],
        access="public final",
        fields=[
            _FakeField("SECRET_KEY", "Ljava/lang/String;", "private static final"),
            _FakeField("count", "I", "private"),
        ],
        methods=3,
    )
    client = _patch(monkeypatch, [klass])
    info = client.class_info(tmp_path / "app.apk", "Lcom/example/Pinner;")
    assert info["class_name"] == "Lcom/example/Pinner;"
    assert info["superclass"] == "Landroid/app/Activity;"
    assert info["interfaces"] == [
        "Ljavax/net/ssl/X509TrustManager;",
        "Ljava/lang/Runnable;",
    ]
    assert info["access"] == "public final"
    assert info["field_count"] == 2
    assert info["fields"][0] == {
        "name": "SECRET_KEY",
        "type": "Ljava/lang/String;",
        "access": "private static final",
    }
    assert info["method_count"] == 3
    assert info["is_external"] is False
    assert info["has_more"] is False


def test_apk_class_info_resolves_a_dotted_name(tmp_path: Path, monkeypatch: Any) -> None:
    """A dotted class name must resolve to the smali descriptor internally."""
    klass = _FakeClassAnalysis("Lcom/example/Secret;")
    client = _patch(monkeypatch, [klass])
    info = client.class_info(tmp_path / "app.apk", "com.example.Secret")
    assert info["class_name"] == "Lcom/example/Secret;"
    assert info["superclass"] == "Ljava/lang/Object;"
    assert info["interfaces"] == []


def test_apk_class_info_unknown_class_is_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    client = _patch(monkeypatch, [_FakeClassAnalysis("Lcom/example/Secret;")])
    with pytest.raises(ApkError) as excinfo:
        client.class_info(tmp_path / "app.apk", "com.example.Missing")
    assert excinfo.value.code == "not_found"


def test_apk_class_info_empty_name_is_invalid(tmp_path: Path, monkeypatch: Any) -> None:
    client = _patch(monkeypatch, [_FakeClassAnalysis("Lcom/example/Secret;")])
    with pytest.raises(ApkError) as excinfo:
        client.class_info(tmp_path / "app.apk", "   ")
    assert excinfo.value.code == "invalid_params"


def test_apk_class_info_caps_a_flood_of_fields(tmp_path: Path, monkeypatch: Any) -> None:
    fields = [
        _FakeField(f"f{index}", "I", "private") for index in range(_MAX_FIELDS + 5)
    ]
    klass = _FakeClassAnalysis("Lcom/example/Obf;", fields=fields)
    client = _patch(monkeypatch, [klass])
    info = client.class_info(tmp_path / "app.apk", "Lcom/example/Obf;")
    assert info["field_count"] == _MAX_FIELDS
    assert len(info["fields"]) == _MAX_FIELDS
    assert info["has_more"] is True


def test_apk_class_info_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.class_info")
    assert doc, "apk.class_info is missing its docstring"
    assert "superclass" in doc
    assert "interfaces" in doc
    assert "X509TrustManager" in doc
    assert "field_count" in doc
    assert "method_count" in doc
