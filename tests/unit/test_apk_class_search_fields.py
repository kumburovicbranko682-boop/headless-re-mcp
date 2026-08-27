"""apk.class_search finds classes by name fragment over the DEX class table.

The fake parsed APK stands in for androguard's analysis.get_classes so the
case-insensitive substring match, external-class skip, sorting, bounding and
pagination are what actually get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_CLASSES_COLLECT,
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


class _FakeClass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def _client(classes: list[_FakeClass]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(classes)  # type: ignore[method-assign]
    return client


def test_class_search_matches_substring_case_insensitively_and_sorts() -> None:
    """A fragment matches the smali name ignoring case, sorted, external skipped.

    Measured: "crypto" finds both a lowercase and mixed-case class, drops a
    non-match, and the field is classes carrying the smali names.
    """
    client = _client(
        [
            _FakeClass("Lcom/app/CryptoUtil;"),
            _FakeClass("Lcom/app/crypto/Aes;"),
            _FakeClass("Lcom/app/Login;"),
            _FakeClass("Landroidx/Crypto;", external=True),
        ]
    )
    payload = client.search_classes(Path("dummy.apk"), "crypto")
    assert payload["classes"] == [
        "Lcom/app/CryptoUtil;",
        "Lcom/app/crypto/Aes;",
    ]
    assert payload["query"] == "crypto"
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_class_search_sorted_and_paginated() -> None:
    """A full page reports has_more with a stable, sorted window."""
    classes = [_FakeClass(f"Lp/C{i:03d};") for i in range(25)]
    client = _client(classes)
    first = client.search_classes(Path("dummy.apk"), "lp/c", offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    assert first["classes"][0] == "Lp/C000;"
    second = client.search_classes(Path("dummy.apk"), "lp/c", offset=10, limit=10)
    assert second["offset"] == 10
    assert second["classes"][0] != first["classes"][0]


def test_class_search_scan_capped_over_collection_ceiling() -> None:
    """More matches than the collection ceiling sets scan_capped."""
    classes = [_FakeClass(f"Lm/C{i:05d};") for i in range(_MAX_CLASSES_COLLECT + 40)]
    payload = _client(classes).search_classes(
        Path("dummy.apk"), "lm/c", offset=0, limit=1000
    )
    assert payload["total"] == _MAX_CLASSES_COLLECT
    assert payload["scan_capped"] is True


def test_class_search_empty_when_no_match() -> None:
    """A fragment nothing carries answers with an empty list, not an error."""
    payload = _client([_FakeClass("La;")]).search_classes(Path("dummy.apk"), "zzz")
    assert payload["classes"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_class_search_requires_a_query() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client([_FakeClass("La;")]).search_classes(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_class_search_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.class_search")
    assert "Answers with classes" in doc
    assert "scan_capped" in doc
    assert "substring" in doc
