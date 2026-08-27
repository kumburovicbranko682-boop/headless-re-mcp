"""apk.resources reads the resources.arsc string table, not the DEX pool.

apk.strings only reaches the DEX string constants; hardcoded endpoints, keys
and labels frequently live in resources.arsc instead. These pin the new
reader's shape: a flat (package, locale, name, value) list sorted for stable
paging, None-valued public names skipped, the collection cap surfaced as
scan_capped, and a resource-less apk answering with an empty list plus a note
rather than a backend error. The docstring must name the fields the parser
actually returns.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk import client as apk_client
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


class _FakeArsc:
    def __init__(self, resolved: Any, packages: list[str]) -> None:
        self._resolved = resolved
        self._packages = packages

    def get_resolved_strings(self) -> Any:
        return self._resolved

    def get_packages_names(self) -> list[str]:
        return self._packages


class _FakeApk:
    def __init__(self, arsc: _FakeArsc | None) -> None:
        self._arsc = arsc

    def get_android_resources(self) -> _FakeArsc | None:
        return self._arsc


def _client_with(resolved: Any, packages: list[str] | None = None) -> ApkClient:
    client = ApkClient()
    arsc = _FakeArsc(resolved, packages or ["com.example.app"])
    client._apk = lambda _path: _FakeApk(arsc)  # type: ignore[method-assign, assignment]
    return client


def test_resources_returns_flat_sorted_entries_skipping_none_values() -> None:
    """resolved is {package: {locale: {name: value}}}; None values carry no data."""
    resolved = {
        "com.example.app": {
            "DEFAULT": {
                "api_url": "https://api.example.com",
                "app_name": "Example",
                "unused": None,
            },
            "fr": {
                "app_name": "Exemple",
            },
        }
    }
    client = _client_with(resolved)
    payload = client.resources(Path("dummy.apk"), offset=0, limit=100)
    assert "strings" not in payload
    assert "items" not in payload
    entries = payload["resources"]
    # DEFAULT sorts before fr; api_url before app_name; the None-valued
    # unused name is dropped, so three entries survive.
    assert [(e["locale"], e["name"]) for e in entries] == [
        ("DEFAULT", "api_url"),
        ("DEFAULT", "app_name"),
        ("fr", "app_name"),
    ]
    assert entries[0]["value"] == "https://api.example.com"
    assert entries[0]["package"] == "com.example.app"
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["packages"] == ["com.example.app"]
    assert payload["packages_has_more"] is False


def test_resources_pagination_reports_has_more() -> None:
    resolved = {
        "p": {"DEFAULT": {f"name{index:03d}": f"v{index}" for index in range(25)}}
    }
    client = _client_with(resolved, packages=["p"])
    payload = client.resources(Path("dummy.apk"), offset=0, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    assert payload["offset"] == 0
    # The next page continues from where this one stopped.
    page2 = client.resources(Path("dummy.apk"), offset=10, limit=10)
    assert page2["resources"][0]["name"] == "name010"


def test_resources_scan_capped_when_collection_hits_the_cap(monkeypatch: Any) -> None:
    """total is a floor once the collection cap trips; scan_capped says so."""
    monkeypatch.setattr(apk_client, "_MAX_RESOURCES_COLLECT", 5)
    resolved = {
        "p": {"DEFAULT": {f"name{index:03d}": f"v{index}" for index in range(20)}}
    }
    client = _client_with(resolved, packages=["p"])
    payload = client.resources(Path("dummy.apk"), offset=0, limit=100)
    assert payload["total"] == 5
    assert payload["scan_capped"] is True


def test_resources_without_arsc_is_an_empty_table_not_an_error() -> None:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(None)  # type: ignore[method-assign, assignment]
    payload = client.resources(Path("dummy.apk"), offset=0, limit=100)
    assert payload["resources"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["packages"] == []
    assert "note" in payload


def test_resources_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("apk.resources")
    assert "Answers with resources" in doc
    assert "has_more" in doc
    assert "resources.arsc" in doc
