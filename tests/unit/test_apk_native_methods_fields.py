"""apk.native_methods lists JNI entry points (methods flagged native)."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
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
    def __init__(
        self,
        class_name: str,
        name: str,
        descriptor: str,
        access: str,
        *,
        external: bool = False,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return list(self._methods)


def _client(methods: list[_FakeMethod]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(methods)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_native_methods_keeps_only_the_native_flag() -> None:
    """A method counts only when native is one of its access-flag tokens.

    "nativeHelper" is a red herring -- its name contains the word but its
    flags do not -- so only the two genuinely native-flagged methods return.
    """
    methods = [
        _FakeMethod("Lcom/example/Crypto;", "sign", "([B)[B", "public native"),
        _FakeMethod("Lcom/example/Crypto;", "init", "()V", "private static native"),
        _FakeMethod("Lcom/example/Crypto;", "helper", "()V", "public"),
        _FakeMethod("Lcom/example/Crypto;", "nativeHelper", "()V", "public final"),
    ]
    payload = _client(methods).native_methods(Path("dummy.apk"))
    names = [row["name"] for row in payload["native_methods"]]
    assert names == ["init", "sign"]
    assert payload["total"] == 2
    assert payload["count"] == 2
    first = payload["native_methods"][0]
    assert first["class_name"] == "Lcom/example/Crypto;"
    assert first["name"] == "init"
    assert first["descriptor"] == "()V"
    assert first["access"] == "private static native"


def test_native_methods_skip_external() -> None:
    """External (referenced, not defined here) methods have no native body."""
    methods = [
        _FakeMethod("Landroid/Api;", "draw", "()V", "public native", external=True),
        _FakeMethod("Lcom/example/A;", "run", "()V", "public native"),
    ]
    payload = _client(methods).native_methods(Path("dummy.apk"))
    assert [row["class_name"] for row in payload["native_methods"]] == ["Lcom/example/A;"]
    assert payload["total"] == 1


def test_native_methods_sorted_and_deduped() -> None:
    """Rows are unique per (class, name, descriptor) and sorted by that key."""
    dup = _FakeMethod("Lcom/example/Z;", "a", "()V", "public native")
    methods = [
        _FakeMethod("Lcom/example/Z;", "b", "()V", "public native"),
        _FakeMethod("Lcom/example/A;", "z", "()V", "public native"),
        dup,
        _FakeMethod("Lcom/example/Z;", "a", "()V", "public native"),
    ]
    payload = _client(methods).native_methods(Path("dummy.apk"))
    keys = [(row["class_name"], row["name"]) for row in payload["native_methods"]]
    assert keys == [
        ("Lcom/example/A;", "z"),
        ("Lcom/example/Z;", "a"),
        ("Lcom/example/Z;", "b"),
    ]
    assert payload["total"] == 3


def test_native_methods_paginates() -> None:
    """offset/limit page the sorted list and has_more marks the boundary."""
    methods = [
        _FakeMethod(f"Lcom/example/C{index:03d};", "jni", "()V", "public native")
        for index in range(5)
    ]
    payload = _client(methods).native_methods(Path("dummy.apk"), offset=2, limit=2)
    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [row["class_name"] for row in payload["native_methods"]] == [
        "Lcom/example/C002;",
        "Lcom/example/C003;",
    ]


def test_native_methods_empty_when_none_native() -> None:
    methods = [_FakeMethod("Lcom/example/A;", "run", "()V", "public")]
    payload = _client(methods).native_methods(Path("dummy.apk"))
    assert payload["native_methods"] == []
    assert payload["total"] == 0
    assert payload["count"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_native_methods_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.native_methods")
    assert "Answers with native_methods" in doc
    assert "native_libs" in doc
    assert "descriptor" in doc
