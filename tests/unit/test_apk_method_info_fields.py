"""apk.method_info parses a method's proto and decodes its access flags.

The proto and access decoders are pure; the lookup is driven through a fake
parsed analysis that mimics androguard's MethodAnalysis (name/descriptor/access).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _decode_method_access,
    _parse_dalvik_proto,
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


class _FakeMethod:
    def __init__(self, name: str, descriptor: str, access: str) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access


class _FakeClass:
    def __init__(self, name: str, methods: list[_FakeMethod]) -> None:
        self.name = name
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeAnalysis:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


class _FakeParsed:
    def __init__(self, analysis: _FakeAnalysis) -> None:
        self.analysis = analysis


def _client() -> ApkClient:
    crypto = _FakeClass(
        "Lcom/example/Crypto;",
        [
            _FakeMethod("decrypt", "(Ljava/lang/String; I)[B", "public static"),
            _FakeMethod("decrypt", "([B)[B", "public"),
            _FakeMethod("nativeInit", "()V", "public native"),
            _FakeMethod("<init>", "()V", "public constructor"),
        ],
    )
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(_FakeAnalysis([crypto]))  # type: ignore[method-assign]
    return client


# --- pure descriptor parsing ------------------------------------------------


def test_parse_proto_reads_params_and_return() -> None:
    parsed = _parse_dalvik_proto("(Ljava/lang/String; I[B)V")
    assert parsed["parsed"] is True
    assert parsed["params"] == ["java.lang.String", "int", "byte[]"]
    assert parsed["return_type"] == "void"


def test_parse_proto_handles_object_return_and_no_params() -> None:
    parsed = _parse_dalvik_proto("()Ljava/lang/String;")
    assert parsed["params"] == []
    assert parsed["return_type"] == "java.lang.String"


def test_parse_proto_rejects_a_non_proto() -> None:
    parsed = _parse_dalvik_proto("not a proto")
    assert parsed["parsed"] is False
    assert parsed["params"] == []


# --- pure access decoding ---------------------------------------------------


def test_decode_access_static_native_has_no_code() -> None:
    flags = _decode_method_access("public static native")
    assert flags["is_public"] is True
    assert flags["is_static"] is True
    assert flags["is_native"] is True
    assert flags["has_code"] is False


def test_decode_access_plain_method_has_code() -> None:
    flags = _decode_method_access("private final")
    assert flags["is_private"] is True
    assert flags["is_final"] is True
    assert flags["has_code"] is True


# --- end-to-end through the fake analysis -----------------------------------


def test_method_info_returns_all_overloads() -> None:
    payload = _client().method_info(Path("d.apk"), "com.example.Crypto", "decrypt")
    assert payload["class_name"] == "Lcom/example/Crypto;"
    assert payload["method_name"] == "decrypt"
    assert payload["count"] == 2
    descriptors = {m["descriptor"] for m in payload["methods"]}
    assert descriptors == {"(Ljava/lang/String; I)[B", "([B)[B"}


def test_method_info_resolves_signature_and_flags() -> None:
    payload = _client().method_info(Path("d.apk"), "com.example.Crypto", "decrypt")
    static = next(
        m for m in payload["methods"] if m["descriptor"] == "(Ljava/lang/String; I)[B"
    )
    assert static["params"] == ["java.lang.String", "int"]
    assert static["return_type"] == "byte[]"
    assert static["is_static"] is True
    assert static["has_code"] is True


def test_method_info_flags_native_without_code() -> None:
    payload = _client().method_info(Path("d.apk"), "com.example.Crypto", "nativeInit")
    native = payload["methods"][0]
    assert native["is_native"] is True
    assert native["has_code"] is False


def test_method_info_missing_method_is_not_found() -> None:
    with pytest.raises(ApkError) as caught:
        _client().method_info(Path("d.apk"), "com.example.Crypto", "ghost")
    assert caught.value.code == "not_found"


def test_method_info_missing_class_is_not_found() -> None:
    with pytest.raises(ApkError) as caught:
        _client().method_info(Path("d.apk"), "com.example.Nope", "decrypt")
    assert caught.value.code == "not_found"


def test_apk_method_info_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.method_info")
    assert "has_code" in doc
    assert "signature_parsed" in doc
    assert "return_type" in doc
    assert "is_native" in doc
