"""apk.class_info reports a class's superclass, interfaces, access and fields.

The type/access decoders are pure; the lookup is driven through a fake parsed
analysis that mimics androguard's ClassAnalysis/FieldAnalysis/EncodedField.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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


class _EncodedField:
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


class _FieldAnalysis:
    def __init__(self, encoded: _EncodedField) -> None:
        self._encoded = encoded

    def get_field(self) -> _EncodedField:
        return self._encoded


class _VmClass:
    def __init__(self, access: str) -> None:
        self._access = access

    def get_access_flags_string(self) -> str:
        return self._access


class _ClassAnalysis:
    def __init__(
        self,
        name: str,
        *,
        extends: str,
        implements: list[str],
        access: str,
        fields: list[_FieldAnalysis],
        nb_methods: int,
        external: bool = False,
    ) -> None:
        self.name = name
        self.extends = extends
        self.implements = implements
        self._access = access
        self._fields = fields
        self._nb_methods = nb_methods
        self._external = external

    def get_vm_class(self) -> _VmClass:
        return _VmClass(self._access)

    def get_fields(self) -> list[_FieldAnalysis]:
        return self._fields

    def get_nb_methods(self) -> int:
        return self._nb_methods

    def is_external(self) -> bool:
        return self._external


class _Analysis:
    def __init__(self, classes: list[_ClassAnalysis]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_ClassAnalysis]:
        return self._classes


class _Parsed:
    def __init__(self, analysis: _Analysis) -> None:
        self.analysis = analysis


def _client() -> ApkClient:
    model = _ClassAnalysis(
        "Lcom/example/User;",
        extends="Landroid/os/Parcelable;",
        implements=["Ljava/io/Serializable;", "Ljava/lang/Runnable;"],
        access="public final",
        fields=[
            _FieldAnalysis(_EncodedField("apiKey", "Ljava/lang/String;", "private static final")),
            _FieldAnalysis(_EncodedField("buffer", "[B", "private")),
        ],
        nb_methods=5,
    )
    client = ApkClient()
    client._parsed = lambda _path: _Parsed(_Analysis([model]))  # type: ignore[method-assign]
    return client


def test_class_info_reports_superclass_and_interfaces() -> None:
    payload = _client().class_info(Path("d.apk"), "com.example.User")
    assert payload["class_name"] == "Lcom/example/User;"
    assert payload["superclass"] == "android.os.Parcelable"
    assert payload["interfaces"] == ["java.io.Serializable", "java.lang.Runnable"]
    assert payload["method_count"] == 5
    assert payload["external"] is False


def test_class_info_decodes_class_access() -> None:
    payload = _client().class_info(Path("d.apk"), "com.example.User")
    assert payload["is_public"] is True
    assert payload["is_final"] is True
    assert payload["is_interface"] is False


def test_class_info_lists_fields_with_types_and_flags() -> None:
    payload = _client().class_info(Path("d.apk"), "com.example.User")
    fields = {f["name"]: f for f in payload["fields"]}
    assert payload["field_count"] == 2

    api = fields["apiKey"]
    assert api["type"] == "java.lang.String"
    assert api["is_static"] is True
    assert api["is_final"] is True
    assert api["is_private"] is True

    buf = fields["buffer"]
    assert buf["type"] == "byte[]"
    assert buf["is_static"] is False


def test_class_info_missing_class_is_not_found() -> None:
    with pytest.raises(ApkError) as caught:
        _client().class_info(Path("d.apk"), "com.example.Ghost")
    assert caught.value.code == "not_found"


def test_apk_class_info_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.class_info")
    assert "superclass" in doc
    assert "interfaces" in doc
    assert "field_count" in doc
    assert "method_count" in doc
