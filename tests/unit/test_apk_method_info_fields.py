"""apk.method_info reports one method's parsed signature and decoded flags.

These mock the parsed analysis so the shaping is pinned without a DEX: the
descriptor split into params/return, the access flags decoded to booleans (the
load-bearing is_native / has_code pair), dotted-name resolution, the overload
disambiguation, an external method, the not_found / invalid_params errors, and
the docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _parse_method_descriptor,
    _split_type_list,
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


class _FakeEncoded:
    def __init__(self, flags: int, has_code: bool, access_str: str = "") -> None:
        self._flags = flags
        self._has_code = has_code
        self._access_str = access_str

    def get_access_flags(self) -> int:
        return self._flags

    def get_code(self) -> object | None:
        return object() if self._has_code else None

    def get_access_flags_string(self) -> str:
        return self._access_str


class _FakeMethodAnalysis:
    def __init__(
        self,
        name: str,
        descriptor: str,
        access: str,
        *,
        flags: int = 0,
        has_code: bool = False,
        external: bool = False,
        enc: bool = True,
        enc_access_str: str = "",
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._external = external
        self._enc = _FakeEncoded(flags, has_code, enc_access_str) if enc else None

    def is_external(self) -> bool:
        return self._external

    def get_method(self) -> _FakeEncoded | None:
        return self._enc


class _FakeClassAnalysis:
    def __init__(self, name: str, methods: list[_FakeMethodAnalysis]) -> None:
        self.name = name
        self._methods = methods

    def get_methods(self) -> list[_FakeMethodAnalysis]:
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


def test_split_type_list_handles_arrays_objects_and_primitives() -> None:
    assert _split_type_list("Ljava/lang/String;[BI") == ["Ljava/lang/String;", "[B", "I"]
    assert _split_type_list("") == []
    assert _split_type_list("[[Lcom/x/Y;J") == ["[[Lcom/x/Y;", "J"]
    # A malformed L-run with no semicolon is emitted whole, not dropped.
    assert _split_type_list("Lbroken") == ["Lbroken"]


def test_parse_method_descriptor_splits_params_and_return() -> None:
    assert _parse_method_descriptor("()V") == ([], "V")
    assert _parse_method_descriptor("(Ljava/lang/String;[BI)Ljava/lang/String;") == (
        ["Ljava/lang/String;", "[B", "I"],
        "Ljava/lang/String;",
    )
    # Not the (params)return shape: degrade to empty rather than error.
    assert _parse_method_descriptor("garbage") == ([], "")


def test_apk_method_info_decodes_a_native_method(tmp_path: Path, monkeypatch: Any) -> None:
    # The classic Java->native boundary: public native, no Dalvik body.
    klass = _FakeClassAnalysis(
        "Lcom/example/Secret;",
        [_FakeMethodAnalysis("decrypt", "()V", "public native", flags=0x101, has_code=False)],
    )
    client = _patch(monkeypatch, [klass])
    info = client.method_info(tmp_path / "app.apk", "Lcom/example/Secret;", "decrypt")
    assert info["class_name"] == "Lcom/example/Secret;"
    assert info["name"] == "decrypt"
    assert info["descriptor"] == "()V"
    assert info["params"] == []
    assert info["return_type"] == "V"
    assert info["access"] == "public native"
    assert info["is_native"] is True
    assert info["is_public"] is True
    assert info["is_static"] is False
    assert info["is_external"] is False
    assert info["has_code"] is False


def test_apk_method_info_parses_a_rich_signature(tmp_path: Path, monkeypatch: Any) -> None:
    klass = _FakeClassAnalysis(
        "Lcom/example/Signer;",
        [
            _FakeMethodAnalysis(
                "sign",
                "(Ljava/lang/String;[BI)Ljava/lang/String;",
                "private static",
                flags=0x2 | 0x8,
                has_code=True,
            )
        ],
    )
    client = _patch(monkeypatch, [klass])
    info = client.method_info(tmp_path / "app.apk", "com.example.Signer", "sign")
    assert info["params"] == ["Ljava/lang/String;", "[B", "I"]
    assert info["return_type"] == "Ljava/lang/String;"
    assert info["is_private"] is True
    assert info["is_static"] is True
    assert info["is_native"] is False
    assert info["has_code"] is True


def test_apk_method_info_overload_requires_a_descriptor(
    tmp_path: Path, monkeypatch: Any
) -> None:
    klass = _FakeClassAnalysis(
        "Lcom/example/Over;",
        [
            _FakeMethodAnalysis("run", "()V", "public", flags=0x1, has_code=True),
            _FakeMethodAnalysis("run", "(I)V", "public", flags=0x1, has_code=True),
        ],
    )
    client = _patch(monkeypatch, [klass])
    with pytest.raises(ApkError) as excinfo:
        client.method_info(tmp_path / "app.apk", "Lcom/example/Over;", "run")
    assert excinfo.value.code == "invalid_params"
    assert set(excinfo.value.details["candidates"]) == {"()V", "(I)V"}

    # Passing the exact descriptor picks the one.
    picked = client.method_info(
        tmp_path / "app.apk", "Lcom/example/Over;", "run", descriptor="(I)V"
    )
    assert picked["descriptor"] == "(I)V"
    assert picked["params"] == ["I"]


def test_apk_method_info_external_method_has_no_flags(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # An external method (only seen referenced) has no EncodedMethod: the flag
    # booleans stay false and is_external carries the story; access falls back
    # to the MethodAnalysis string.
    klass = _FakeClassAnalysis(
        "Lcom/example/Ext;",
        [
            _FakeMethodAnalysis(
                "toString", "()Ljava/lang/String;", "public", external=True, enc=False
            )
        ],
    )
    client = _patch(monkeypatch, [klass])
    info = client.method_info(tmp_path / "app.apk", "Lcom/example/Ext;", "toString")
    assert info["is_external"] is True
    assert info["has_code"] is False
    assert info["is_public"] is False
    assert info["access"] == "public"
    assert info["return_type"] == "Ljava/lang/String;"


def test_apk_method_info_unknown_class_is_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    client = _patch(monkeypatch, [_FakeClassAnalysis("Lcom/example/A;", [])])
    with pytest.raises(ApkError) as excinfo:
        client.method_info(tmp_path / "app.apk", "com.example.Missing", "x")
    assert excinfo.value.code == "not_found"


def test_apk_method_info_unknown_method_is_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    klass = _FakeClassAnalysis(
        "Lcom/example/A;", [_FakeMethodAnalysis("real", "()V", "public", flags=0x1)]
    )
    client = _patch(monkeypatch, [klass])
    with pytest.raises(ApkError) as excinfo:
        client.method_info(tmp_path / "app.apk", "Lcom/example/A;", "ghost")
    assert excinfo.value.code == "not_found"


def test_apk_method_info_empty_names_are_invalid(tmp_path: Path, monkeypatch: Any) -> None:
    client = _patch(monkeypatch, [_FakeClassAnalysis("Lcom/example/A;", [])])
    with pytest.raises(ApkError) as first:
        client.method_info(tmp_path / "app.apk", "   ", "x")
    assert first.value.code == "invalid_params"
    with pytest.raises(ApkError) as second:
        client.method_info(tmp_path / "app.apk", "Lcom/example/A;", "  ")
    assert second.value.code == "invalid_params"


def test_apk_method_info_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.method_info")
    assert doc, "apk.method_info is missing its docstring"
    assert "is_native" in doc
    assert "has_code" in doc
    assert "params" in doc
    assert "return_type" in doc
    assert "descriptor" in doc
