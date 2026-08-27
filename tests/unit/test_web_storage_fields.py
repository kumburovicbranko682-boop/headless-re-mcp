"""web.storage reads both Storage areas with honest availability and bounds."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_KEYS,
    _MAX_STORAGE_VALUE_CHARS,
    WebBackend,
    _bound_store,
)
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        del timeout
        return work()


def _backend_with_page(monkeypatch: Any, page: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


class _Page:
    url = "https://app.example/dashboard"

    def evaluate(self, script: str, opts: dict[str, int]) -> dict[str, Any]:
        del script, opts
        return {
            "local": {
                "available": True,
                "count": 2,
                "items_truncated": False,
                "items": [
                    {
                        "key": "auth",
                        "value": "jwt-token",
                        "value_size": 9,
                        "value_truncated": False,
                    },
                    {"key": "flags", "value": "{}", "value_size": 2, "value_truncated": False},
                ],
            },
            "session": {"available": False},
        }


def test_web_storage_maps_both_areas_and_keeps_unavailable_distinct(monkeypatch: Any) -> None:
    """A blocked store reads as available False, not as an empty (token-free) one."""
    backend = _backend_with_page(monkeypatch, _Page())

    payload = backend.storage("s")

    assert payload["url"] == "https://app.example/dashboard"
    local = payload["local"]
    assert local["available"] is True
    assert local["count"] == 2
    assert [item["key"] for item in local["items"]] == ["auth", "flags"]
    assert local["items"][0]["value"] == "jwt-token"
    assert local["items"][0]["value_size"] == 9
    assert "value_truncated" not in local["items"][0]
    assert "items_truncated" not in local
    session = payload["session"]
    assert session == {"available": False, "items": [], "count": 0}

    doc = _tool_docstring("web.storage")
    for token in ("available", "items", "value_size", "count", "items_truncated"):
        assert token in doc


class _PageBig:
    url = "https://x/"

    def evaluate(self, script: str, opts: dict[str, int]) -> dict[str, Any]:
        del script, opts
        big = "v" * (_MAX_STORAGE_VALUE_CHARS + 100)
        items = [
            {"key": f"k{index}", "value": big, "value_size": len(big), "value_truncated": False}
            for index in range(_MAX_STORAGE_KEYS + 5)
        ]
        return {
            "local": {
                "available": True,
                "count": _MAX_STORAGE_KEYS + 5,
                "items": items,
                "items_truncated": True,
            },
            "session": {"available": True, "count": 0, "items": []},
        }


def test_web_storage_bounds_key_count_and_value_size(monkeypatch: Any) -> None:
    """Python re-bounds even values the page under-reported as untruncated."""
    backend = _backend_with_page(monkeypatch, _PageBig())

    payload = backend.storage("s")

    local = payload["local"]
    assert len(local["items"]) == _MAX_STORAGE_KEYS
    assert local["items_truncated"] is True
    assert local["count"] == _MAX_STORAGE_KEYS + 5
    first = local["items"][0]
    assert len(first["value"]) == _MAX_STORAGE_VALUE_CHARS
    assert first["value_truncated"] is True
    assert first["value_size"] == _MAX_STORAGE_VALUE_CHARS + 100

    session = payload["session"]
    assert session["available"] is True
    assert session["count"] == 0
    assert session["items"] == []
    assert "items_truncated" not in session


def test_bound_store_unavailable_and_empty_are_different() -> None:
    assert _bound_store(None) == {"available": False, "items": [], "count": 0}
    assert _bound_store({"available": False}) == {"available": False, "items": [], "count": 0}
    empty = _bound_store({"available": True, "count": 0, "items": []})
    assert empty == {"available": True, "items": [], "count": 0}


def test_bound_store_flags_a_count_larger_than_the_returned_items() -> None:
    """A store that reported 5 keys but handed back none is truncated, not empty."""
    out = _bound_store({"available": True, "count": 5, "items": []})
    assert out["count"] == 5
    assert out["items"] == []
    assert out["items_truncated"] is True


def test_bound_store_skips_malformed_entries() -> None:
    out = _bound_store(
        {
            "available": True,
            "count": 3,
            "items": [
                {"key": "ok", "value": "v", "value_size": 1},
                {"key": 123, "value": "bad-key"},
                "not-a-dict",
            ],
        }
    )
    assert [item["key"] for item in out["items"]] == ["ok"]
