"""apk.method_search finds methods by name fragment across every class.

The fake parsed APK stands in for androguard's analysis.get_methods so the
case-insensitive substring match, external-method skip, sorting, bounding and
pagination are what actually get exercised.
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


class _FakeMethod:
    def __init__(
        self,
        class_name: str,
        name: str,
        descriptor: str = "()V",
        *,
        external: bool = False,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self._external = external

    def is_external(self) -> bool:
        return self._external


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


def test_method_search_matches_name_substring_case_insensitively() -> None:
    """A fragment matches on the method name only, ignoring case.

    Measured: "crypt" finds decrypt and Encrypt but not a class that merely
    contains the fragment in its name, and the field is methods with class,
    method, descriptor.
    """
    client = _client(
        [
            _FakeMethod("La;", "decrypt", "(Ljava/lang/String;)V"),
            _FakeMethod("Lb;", "Encrypt"),
            _FakeMethod("Lcrypto/Helper;", "run"),
            _FakeMethod("Lc;", "unrelated"),
        ]
    )
    payload = client.search_methods(Path("dummy.apk"), "crypt")
    assert payload["methods"] == [
        {"class": "La;", "method": "decrypt", "descriptor": "(Ljava/lang/String;)V"},
        {"class": "Lb;", "method": "Encrypt", "descriptor": "()V"},
    ]
    assert payload["query"] == "crypt"
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_method_search_skips_external_methods() -> None:
    """Framework/external methods are not part of the app's own surface."""
    client = _client(
        [
            _FakeMethod("La;", "sign"),
            _FakeMethod("Landroid/Sys;", "signExternal", external=True),
        ]
    )
    payload = client.search_methods(Path("dummy.apk"), "sign")
    assert payload["total"] == 1
    assert payload["methods"][0]["class"] == "La;"


def test_method_search_sorted_and_paginated() -> None:
    """A full page reports has_more with a stable, sorted window."""
    methods = [_FakeMethod(f"L{i:03d};", "handle") for i in range(25)]
    client = _client(methods)
    first = client.search_methods(Path("dummy.apk"), "handle", offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    assert first["methods"][0]["class"] == "L000;"
    second = client.search_methods(Path("dummy.apk"), "handle", offset=10, limit=10)
    assert second["offset"] == 10
    assert second["methods"][0]["class"] != first["methods"][0]["class"]


def test_method_search_scan_capped_over_collection_ceiling() -> None:
    """More matches than the collection ceiling sets scan_capped."""
    methods = [
        _FakeMethod(f"L{i:05d};", "match") for i in range(_MAX_METHODS_COLLECT + 30)
    ]
    payload = _client(methods).search_methods(
        Path("dummy.apk"), "match", offset=0, limit=1000
    )
    assert payload["total"] == _MAX_METHODS_COLLECT
    assert payload["scan_capped"] is True


def test_method_search_empty_when_no_match() -> None:
    """A fragment nothing carries answers with an empty list, not an error."""
    payload = _client([_FakeMethod("La;", "run")]).search_methods(
        Path("dummy.apk"), "zzz"
    )
    assert payload["methods"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_method_search_requires_a_query() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client([_FakeMethod("La;", "run")]).search_methods(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_method_search_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.method_search")
    assert "Answers with methods" in doc
    assert "scan_capped" in doc
    assert "substring" in doc
