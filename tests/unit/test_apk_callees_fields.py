"""apk.callees lists the distinct methods a named method calls.

The fake parsed APK stands in for androguard's analysis.get_methods /
get_xref_to so the de-duplication, sorting, matched flag, cap and error path
are what actually get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import _MAX_XREFS_PAGE, ApkClient, ApkError
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


class _FakeCallee:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeMethod:
    def __init__(
        self, name: str, callees: list[_FakeCallee], *, external: bool = False
    ) -> None:
        self.name = name
        self._callees = callees
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_to(self) -> list[tuple[object, _FakeCallee, int]]:
        return [(None, callee, index) for index, callee in enumerate(self._callees)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def _client(methods: list[_FakeMethod]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(methods)  # type: ignore[method-assign]
    return client


def test_apk_callees_dedupes_and_sorts_targets() -> None:
    """Repeated call sites to one helper collapse to a single sorted callee.

    Measured: onCreate calls findViewById three times and setContentView once
    -> two distinct callees, sorted, matched True, and no callers or xref_to
    field.
    """
    oncreate = _FakeMethod(
        "onCreate",
        [
            _FakeCallee("Landroid/app/Activity;", "findViewById"),
            _FakeCallee("Landroid/app/Activity;", "findViewById"),
            _FakeCallee("Landroid/app/Activity;", "findViewById"),
            _FakeCallee("Landroid/app/Activity;", "setContentView"),
        ],
    )
    payload = _client([oncreate]).callees(Path("dummy.apk"), "onCreate")
    assert payload["callees"] == [
        {"class": "Landroid/app/Activity;", "method": "findViewById"},
        {"class": "Landroid/app/Activity;", "method": "setContentView"},
    ]
    assert payload["count"] == 2
    assert payload["matched"] is True
    assert payload["has_more"] is False
    assert payload["method_name"] == "onCreate"
    assert "callers" not in payload
    assert "xref_to" not in payload


def test_apk_callees_unions_overloads() -> None:
    """Two methods sharing the name contribute a merged, distinct target set."""
    m1 = _FakeMethod("run", [_FakeCallee("La;", "x")])
    m2 = _FakeMethod("run", [_FakeCallee("Lb;", "y")])
    payload = _client([m1, m2]).callees(Path("dummy.apk"), "run")
    assert payload["callees"] == [
        {"class": "La;", "method": "x"},
        {"class": "Lb;", "method": "y"},
    ]
    assert payload["matched"] is True


def test_apk_callees_matched_false_when_no_such_method() -> None:
    """A name no non-external method carries reports matched False, empty list."""
    payload = _client([_FakeMethod("other", [_FakeCallee("La;", "x")])]).callees(
        Path("dummy.apk"), "missing"
    )
    assert payload["matched"] is False
    assert payload["callees"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_apk_callees_matched_true_but_no_callees() -> None:
    """A method that calls nothing is matched True with an empty list."""
    payload = _client([_FakeMethod("leaf", [])]).callees(Path("dummy.apk"), "leaf")
    assert payload["matched"] is True
    assert payload["callees"] == []


def test_apk_callees_caps_distinct_targets_and_flags_has_more() -> None:
    """More distinct targets than the limit sets has_more."""
    many = [_FakeCallee(f"L{i:04d};", "m") for i in range(_MAX_XREFS_PAGE + 5)]
    client = _client([_FakeMethod("big", many)])
    payload = client.callees(Path("dummy.apk"), "big", limit=10)
    assert payload["count"] == 10
    assert payload["has_more"] is True


def test_apk_callees_requires_a_method_name() -> None:
    client = _client([_FakeMethod("x", [])])
    with pytest.raises(ApkError) as excinfo:
        client.callees(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_apk_callees_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.callees")
    assert "Answers with callees" in doc
    assert "matched" in doc
    assert "has_more" in doc
