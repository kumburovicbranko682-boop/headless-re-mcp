"""apk.native_methods lists JNI entry points and mangles their export symbols.

It mocks the parsed analysis with fake classes/methods (native and not) and
checks: only methods flagged native are selected, external classes are skipped,
the jni_symbol is the JNI-spec short name (dots/slashes to _, underscore escaped
to _1, inner-class $ to _00024), rows sort by class then method, pagination and
the collect ceiling behave, plus direct tests of the mangling helpers and the
tool docstring.
"""

from __future__ import annotations

import ast
import types
from pathlib import Path

import headless_re_mcp.backends.apk.client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient, _jni_mangle, _jni_short_symbol
from headless_re_mcp.tools.apk import build_apk_tools


class _M:
    def __init__(self, class_name: str, name: str, access: str, descriptor: str) -> None:
        self.class_name = class_name
        self.name = name
        self.access = access
        self.descriptor = descriptor


class _C:
    def __init__(self, name: str, methods: list[_M], external: bool = False) -> None:
        self.name = name
        self._methods = methods
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[_M]:
        return self._methods


class _Analysis:
    def __init__(self, classes: list[_C]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_C]:
        return self._classes


def _client(classes: list[_C]) -> ApkClient:
    client = ApkClient()
    parsed = types.SimpleNamespace(analysis=_Analysis(classes))
    client._parsed = lambda _path: parsed  # type: ignore[method-assign,return-value]
    return client


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


def test_selects_native_methods_and_builds_symbol() -> None:
    classes = [
        _C(
            "Lcom/example/Foo;",
            [
                _M("Lcom/example/Foo;", "stringFromJNI", "public native", "()Ljava/lang/String;"),
                _M("Lcom/example/Foo;", "regular", "public", "()V"),
            ],
        ),
    ]
    payload = _client(classes).native_methods(Path("d.apk"))
    assert payload["total"] == 1
    row = payload["native_methods"][0]
    assert row == {
        "class": "Lcom/example/Foo;",
        "method": "stringFromJNI",
        "descriptor": "()Ljava/lang/String;",
        "access": "public native",
        "jni_symbol": "Java_com_example_Foo_stringFromJNI",
    }


def test_static_native_flag_is_selected() -> None:
    classes = [_C("La;", [_M("La;", "n", "public static native", "()V")])]
    payload = _client(classes).native_methods(Path("d"))
    assert payload["total"] == 1


def test_external_classes_are_skipped() -> None:
    classes = [
        _C("Lext/Lib;", [_M("Lext/Lib;", "x", "public native", "()V")], external=True),
        _C("Lapp/A;", [_M("Lapp/A;", "y", "native", "()V")]),
    ]
    payload = _client(classes).native_methods(Path("d"))
    assert [r["class"] for r in payload["native_methods"]] == ["Lapp/A;"]


def test_rows_sorted_by_class_then_method() -> None:
    classes = [
        _C(
            "Lb/B;",
            [
                _M("Lb/B;", "zeta", "native", "()V"),
                _M("Lb/B;", "alpha", "native", "()V"),
            ],
        ),
        _C("La/A;", [_M("La/A;", "m", "native", "()V")]),
    ]
    payload = _client(classes).native_methods(Path("d"))
    got = [(r["class"], r["method"]) for r in payload["native_methods"]]
    assert got == [("La/A;", "m"), ("Lb/B;", "alpha"), ("Lb/B;", "zeta")]


def test_pagination_reports_total_and_has_more() -> None:
    methods = [_M("La/A;", f"m{i:02d}", "native", "()V") for i in range(5)]
    payload = _client([_C("La/A;", methods)]).native_methods(Path("d"), offset=1, limit=2)
    assert payload["total"] == 5
    assert payload["count"] == 2
    assert payload["offset"] == 1
    assert [r["method"] for r in payload["native_methods"]] == ["m01", "m02"]
    assert payload["has_more"] is True


def test_collect_ceiling_sets_scan_capped(monkeypatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_NATIVE_COLLECT", 2)
    methods = [_M("La/A;", f"m{i}", "native", "()V") for i in range(5)]
    payload = _client([_C("La/A;", methods)]).native_methods(Path("d"))
    assert payload["scan_capped"] is True
    assert payload["total"] == 2  # collection stopped at the ceiling


def test_jni_short_symbol_basic() -> None:
    assert (
        _jni_short_symbol("Lcom/example/Native;", "stringFromJNI")
        == "Java_com_example_Native_stringFromJNI"
    )


def test_jni_short_symbol_escapes_underscore_and_inner_class() -> None:
    assert _jni_short_symbol("La;", "native_init") == "Java_a_native_1init"
    assert _jni_short_symbol("Lcom/x/Foo$Bar;", "run") == "Java_com_x_Foo_00024Bar_run"


def test_jni_mangle_rules() -> None:
    assert _jni_mangle("a/b.c") == "a_b_c"
    assert _jni_mangle("x_y") == "x_1y"
    assert _jni_mangle("$") == "_00024"
    assert _jni_mangle("A1z9") == "A1z9"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.native_methods")
    assert "Answers with" in doc
    assert "jni_symbol" in doc
    assert "native_methods" in doc
    assert "scan_capped" in doc
