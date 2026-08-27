"""apk.method_info profiles a class's method(s): signature + connectivity."""

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


class _FakeMethod:
    def __init__(
        self,
        class_name: str,
        name: str,
        descriptor: str,
        access: str,
        callers: int,
        callees: int,
        *,
        external: bool = False,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._callers = callers
        self._callees = callees
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, object, int]]:
        return [(None, None, index) for index in range(self._callers)]

    def get_xref_to(self) -> list[tuple[object, object, int]]:
        return [(None, None, index) for index in range(self._callees)]


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


def test_method_info_reports_descriptor_access_and_counts() -> None:
    """Each overload gets its signature and caller/callee counts.

    encrypt has two overloads; only the two on the target class come back,
    each with its own descriptor, access and connectivity counts.
    """
    methods = [
        _FakeMethod("Lcom/example/Enc;", "encrypt", "([B)[B", "public", 5, 3),
        _FakeMethod("Lcom/example/Enc;", "encrypt", "(Ljava/lang/String;)[B", "public", 1, 2),
        _FakeMethod("Lcom/example/Enc;", "decrypt", "([B)[B", "public", 9, 0),
        _FakeMethod("Lcom/example/Other;", "encrypt", "([B)[B", "public", 2, 2),
    ]
    payload = _client(methods).method_info(Path("dummy.apk"), "com.example.Enc", "encrypt")
    assert payload["class_name"] == "Lcom/example/Enc;"
    assert payload["method_name"] == "encrypt"
    assert payload["matched"] is True
    assert payload["total"] == 2
    assert payload["methods"] == [
        {"descriptor": "(Ljava/lang/String;)[B", "access": "public", "callers": 1, "callees": 2},
        {"descriptor": "([B)[B", "access": "public", "callers": 5, "callees": 3},
    ]


def test_method_info_accepts_smali_class() -> None:
    methods = [_FakeMethod("Lcom/example/A;", "run", "()V", "public", 0, 0)]
    payload = _client(methods).method_info(Path("dummy.apk"), "Lcom/example/A;", "run")
    assert payload["matched"] is True
    assert payload["methods"][0]["descriptor"] == "()V"


def test_method_info_skips_external() -> None:
    methods = [
        _FakeMethod("Lcom/example/A;", "run", "()V", "public", 3, 3, external=True),
        _FakeMethod("Lcom/example/A;", "run", "(I)V", "public", 1, 1),
    ]
    payload = _client(methods).method_info(Path("dummy.apk"), "Lcom/example/A;", "run")
    assert payload["total"] == 1
    assert payload["methods"][0]["descriptor"] == "(I)V"


def test_method_info_no_match_is_not_matched() -> None:
    methods = [_FakeMethod("Lcom/example/A;", "run", "()V", "public", 0, 0)]
    payload = _client(methods).method_info(Path("dummy.apk"), "Lcom/example/A;", "missing")
    assert payload["matched"] is False
    assert payload["methods"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_method_info_paginates() -> None:
    methods = [
        _FakeMethod("Lcom/example/A;", "f", f"(I{index:03d})V", "public", index, 0)
        for index in range(5)
    ]
    payload = _client(methods).method_info(
        Path("dummy.apk"), "Lcom/example/A;", "f", offset=1, limit=2
    )
    assert payload["offset"] == 1
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_method_info_requires_class_and_method() -> None:
    client = _client([_FakeMethod("Lcom/example/A;", "run", "()V", "public", 0, 0)])
    with pytest.raises(ApkError) as excinfo_class:
        client.method_info(Path("dummy.apk"), "   ", "run")
    assert excinfo_class.value.code == "invalid_params"
    with pytest.raises(ApkError) as excinfo_method:
        client.method_info(Path("dummy.apk"), "Lcom/example/A;", "   ")
    assert excinfo_method.value.code == "invalid_params"


def test_method_info_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.method_info")
    assert "callers" in doc
    assert "callees" in doc
    assert "descriptor" in doc
    assert "matched" in doc
