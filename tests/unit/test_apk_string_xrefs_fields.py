"""apk.string_xrefs answers "which methods reference this exact string".

apk.strings lists constants and apk.xrefs finds a method's callers, but the
string-to-use-site direction -- the top triage question for a hardcoded URL,
key or message -- had no tool. These pin the reader: exact whitespace-
significant matching, de-duplicated and sorted callers, the matched flag that
separates "no references" from "no such string", the limit cap surfaced as
has_more, and invalid_params for an empty value. The docstring must name the
fields the parser returns.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
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


class _FakeMethodAnalysis:
    def __init__(self, class_name: str, name: str, descriptor: str) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor


class _FakeStringAnalysis:
    def __init__(self, value: str, xrefs: list[_FakeMethodAnalysis]) -> None:
        self._value = value
        self._xrefs = xrefs

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self) -> set[tuple[object, _FakeMethodAnalysis]]:
        return {(object(), method) for method in self._xrefs}


class _FakeParsed:
    def __init__(self, strings: list[_FakeStringAnalysis]) -> None:
        self.analysis = self
        self._strings = strings

    def get_strings(self) -> list[_FakeStringAnalysis]:
        return self._strings


def _client_with(strings: list[_FakeStringAnalysis]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(strings)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_string_xrefs_lists_deduped_sorted_referencing_methods() -> None:
    target = "https://api.example.com"
    methods = [
        _FakeMethodAnalysis("Lcom/example/Net;", "post", "()V"),
        _FakeMethodAnalysis("Lcom/example/Net;", "get", "()V"),
        # duplicate reference from the same method collapses to one row
        _FakeMethodAnalysis("Lcom/example/Net;", "get", "()V"),
    ]
    client = _client_with(
        [
            _FakeStringAnalysis(target, methods),
            _FakeStringAnalysis("unrelated", [_FakeMethodAnalysis("La;", "x", "()V")]),
        ]
    )
    payload = client.string_xrefs(Path("dummy.apk"), target, limit=100)
    assert payload["value"] == target
    assert payload["matched"] is True
    assert payload["callers"] == [
        {"class": "Lcom/example/Net;", "method": "get", "descriptor": "()V"},
        {"class": "Lcom/example/Net;", "method": "post", "descriptor": "()V"},
    ]
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert "method_name" not in payload


def test_matching_is_exact_and_whitespace_significant() -> None:
    client = _client_with(
        [_FakeStringAnalysis(" spaced ", [_FakeMethodAnalysis("La;", "m", "()V")])]
    )
    trimmed = client.string_xrefs(Path("dummy.apk"), "spaced", limit=10)
    assert trimmed["matched"] is False
    assert trimmed["callers"] == []
    exact = client.string_xrefs(Path("dummy.apk"), " spaced ", limit=10)
    assert exact["matched"] is True
    assert exact["count"] == 1


def test_in_pool_string_with_no_callers_is_matched_but_empty() -> None:
    client = _client_with([_FakeStringAnalysis("dead", [])])
    payload = client.string_xrefs(Path("dummy.apk"), "dead", limit=10)
    assert payload["matched"] is True
    assert payload["callers"] == []
    assert payload["total"] == 0


def test_limit_caps_the_page_and_flags_has_more() -> None:
    methods = [
        _FakeMethodAnalysis(f"Lc{index:03d};", "m", "()V") for index in range(25)
    ]
    client = _client_with([_FakeStringAnalysis("s", methods)])
    payload = client.string_xrefs(Path("dummy.apk"), "s", limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True


def test_collection_cap_sets_scan_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(apk_client, "_MAX_STRING_XREFS_COLLECT", 5)
    methods = [
        _FakeMethodAnalysis(f"Lc{index:03d};", "m", "()V") for index in range(20)
    ]
    client = _client_with([_FakeStringAnalysis("s", methods)])
    payload = client.string_xrefs(Path("dummy.apk"), "s", limit=1000)
    assert payload["total"] == 5
    assert payload["scan_capped"] is True
    assert payload["has_more"] is True


def test_empty_value_is_invalid_params() -> None:
    client = _client_with([])
    with pytest.raises(ApkError) as excinfo:
        client.string_xrefs(Path("dummy.apk"), "", limit=10)
    assert excinfo.value.code == "invalid_params"


def test_string_xrefs_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("apk.string_xrefs")
    assert "Answers with callers" in doc
    assert "matched" in doc
    assert "has_more" in doc
