"""apk.native_methods enumerates JNI native methods across the DEX.

Driven through the _parsed seam with a fake analysis mimicking androguard's
get_classes() / ClassAnalysis.get_methods() and the .name/.descriptor/.access
attributes those method views carry.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _jni_short_name
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


class _Method:
    def __init__(self, name: str, descriptor: str, access: str) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access


class _ClassAnalysis:
    def __init__(self, name: str, methods: list[_Method], *, external: bool = False) -> None:
        self.name = name
        self._methods = methods
        self._external = external

    def get_methods(self) -> list[_Method]:
        return self._methods

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


def _client(classes: list[_ClassAnalysis]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _Parsed(_Analysis(classes))  # type: ignore[method-assign]
    return client


def test_jni_short_name_mangles_class_and_method() -> None:
    assert _jni_short_name("Lcom/example/Foo;", "doIt") == "Java_com_example_Foo_doIt"
    # A literal underscore in the method name mangles to _1.
    assert _jni_short_name("Lcom/example/Foo;", "do_it") == "Java_com_example_Foo_do_1it"


def test_native_methods_keeps_only_native_declarations() -> None:
    classes = [
        _ClassAnalysis(
            "Lcom/example/Crypto;",
            [
                _Method("nativeDecrypt", "([B)[B", "public native"),
                _Method("helper", "()V", "private"),
            ],
        ),
        _ClassAnalysis(
            "Lcom/example/Loader;",
            [_Method("init", "()I", "public static native")],
        ),
        _ClassAnalysis(
            "Lcom/external/Stub;",
            [_Method("ignored", "()V", "public native")],
            external=True,
        ),
    ]
    payload = _client(classes).native_methods(Path("d.apk"))
    # Two native methods, external class skipped, non-native skipped.
    assert payload["total"] == 2
    by_method = {r["method"]: r for r in payload["native_methods"]}
    assert set(by_method) == {"nativeDecrypt", "init"}

    dec = by_method["nativeDecrypt"]
    assert dec["class"] == "com.example.Crypto"
    assert dec["params"] == ["byte[]"]
    assert dec["return_type"] == "byte[]"
    assert dec["jni_symbol"] == "Java_com_example_Crypto_nativeDecrypt"


def test_native_methods_sorted_and_paged() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [
                _Method("m2", "()V", "native"),
                _Method("m1", "()V", "native"),
                _Method("m3", "()V", "native"),
            ],
        )
    ]
    payload = _client(classes).native_methods(Path("d.apk"), offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 3
    assert payload["has_more"] is True
    # Sorted by class then method: m1 comes first.
    assert payload["native_methods"][0]["method"] == "m1"


def test_native_methods_on_an_app_with_no_native_code() -> None:
    classes = [_ClassAnalysis("Lc/A;", [_Method("run", "()V", "public")])]
    payload = _client(classes).native_methods(Path("d.apk"))
    assert payload["total"] == 0
    assert payload["native_methods"] == []


def test_apk_native_methods_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.native_methods")
    assert "jni_symbol" in doc
    assert "native_methods" in doc
    assert "scan_capped" in doc
