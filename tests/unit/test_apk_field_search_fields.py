"""apk.field_search substring-matches field names across the whole app."""

from __future__ import annotations

import ast
from pathlib import Path

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


class _FakeEncodedField:
    def __init__(self, class_name: str, name: str, descriptor: str, access: str) -> None:
        self._class_name = class_name
        self._name = name
        self._descriptor = descriptor
        self._access = access

    def get_name(self) -> str:
        return self._name

    def get_class_name(self) -> str:
        return self._class_name

    def get_descriptor(self) -> str:
        return self._descriptor

    def get_access_flags_string(self) -> str:
        return self._access


class _FakeFieldAnalysis:
    def __init__(self, class_name: str, name: str, descriptor: str, access: str) -> None:
        self._encoded = _FakeEncodedField(class_name, name, descriptor, access)

    def get_field(self) -> _FakeEncodedField:
        return self._encoded


class _FakeParsed:
    def __init__(self, fields: list[_FakeFieldAnalysis]) -> None:
        self.analysis = self
        self._fields = fields

    def get_fields(self) -> list[_FakeFieldAnalysis]:
        return list(self._fields)


def _client(fields: list[_FakeFieldAnalysis]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(fields)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_field_search_matches_substring_case_insensitively() -> None:
    """The query matches the simple field name regardless of case.

    "key" hits API_KEY and mKeyStore but not baseUrl, and each row carries the
    declaring class, descriptor and access.
    """
    fields = [
        _FakeFieldAnalysis(
            "Lcom/example/Cfg;", "API_KEY", "Ljava/lang/String;", "public static final"
        ),
        _FakeFieldAnalysis("Lcom/example/Sec;", "mKeyStore", "Ljava/security/KeyStore;", "private"),
        _FakeFieldAnalysis("Lcom/example/Net;", "baseUrl", "Ljava/lang/String;", "private"),
    ]
    payload = _client(fields).search_fields(Path("dummy.apk"), "key")
    assert payload["query"] == "key"
    assert payload["fields"] == [
        {
            "class_name": "Lcom/example/Cfg;",
            "name": "API_KEY",
            "descriptor": "Ljava/lang/String;",
            "access": "public static final",
        },
        {
            "class_name": "Lcom/example/Sec;",
            "name": "mKeyStore",
            "descriptor": "Ljava/security/KeyStore;",
            "access": "private",
        },
    ]
    assert payload["total"] == 2


def test_field_search_dedups_and_sorts() -> None:
    fields = [
        _FakeFieldAnalysis("Lz/A;", "token", "I", "public"),
        _FakeFieldAnalysis("La/A;", "token", "I", "public"),
        _FakeFieldAnalysis("La/A;", "token", "I", "public"),
    ]
    payload = _client(fields).search_fields(Path("dummy.apk"), "token")
    assert [row["class_name"] for row in payload["fields"]] == ["La/A;", "Lz/A;"]
    assert payload["total"] == 2


def test_field_search_no_match_is_empty() -> None:
    fields = [_FakeFieldAnalysis("Lcom/a/B;", "count", "I", "private")]
    payload = _client(fields).search_fields(Path("dummy.apk"), "secret")
    assert payload["fields"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_field_search_paginates() -> None:
    fields = [
        _FakeFieldAnalysis(f"Lc/C{index:03d};", "flag", "Z", "public") for index in range(5)
    ]
    payload = _client(fields).search_fields(Path("dummy.apk"), "flag", offset=2, limit=2)
    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_field_search_collect_cap_sets_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_METHODS_COLLECT", 2)
    fields = [
        _FakeFieldAnalysis(f"Lc/C{index:03d};", "apiKey", "Ljava/lang/String;", "private")
        for index in range(6)
    ]
    payload = _client(fields).search_fields(Path("dummy.apk"), "key")
    assert payload["scan_capped"] is True
    assert payload["total"] == 2


def test_field_search_requires_query() -> None:
    client = _client([_FakeFieldAnalysis("Lc/A;", "x", "I", "public")])
    with pytest.raises(ApkError) as excinfo:
        client.search_fields(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_field_search_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.field_search")
    assert "Answers with" in doc
    assert "descriptor" in doc
    assert "class_name" in doc
