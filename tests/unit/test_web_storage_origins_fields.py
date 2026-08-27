"""web.storage.origins snapshots per-origin localStorage, bounded and paged.

The fake context returns a Playwright-shaped storage_state dict so the Python
aggregation, sorting, value-bounding, per-origin caps and pagination are what
actually get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_ORIGIN_STORAGE_VALUE,
    _MAX_STORAGE_ORIGIN_ENTRIES,
    _MAX_STORAGE_ORIGINS,
    WebBackend,
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
        return work()


class _Context:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def storage_state(self) -> dict[str, Any]:
        return self._state


def _backend(monkeypatch: Any, state: dict[str, Any]) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(context=_Context(state))
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_storage_origins_aggregates_sorts_and_drops_cookies(monkeypatch: Any) -> None:
    """Origins come back sorted, entries sorted by name, cookies omitted.

    Measured: two origins ordered by origin string, each origin's localStorage
    sorted by name with entry_count/entry_total, and no cookies or
    sessionStorage field leaking from storage_state.
    """
    state = {
        "cookies": [{"name": "sid", "value": "x"}],
        "origins": [
            {
                "origin": "https://idp.example",
                "localStorage": [
                    {"name": "token", "value": "jwt"},
                    {"name": "auth", "value": "1"},
                ],
            },
            {
                "origin": "https://app.example",
                "localStorage": [{"name": "flag", "value": "on"}],
            },
        ],
    }
    payload = _backend(monkeypatch, state).storage_origins("s")
    assert [o["origin"] for o in payload["origins"]] == [
        "https://app.example",
        "https://idp.example",
    ]
    idp = payload["origins"][1]
    assert [e["name"] for e in idp["local"]] == ["auth", "token"]
    assert idp["entry_count"] == 2
    assert idp["entry_total"] == 2
    assert idp["entries_truncated"] is False
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert payload["origins_capped"] is False
    assert "cookies" not in payload
    assert "sessionStorage" not in payload


def test_storage_origins_bounds_long_values(monkeypatch: Any) -> None:
    """A value over the cap is cut and flagged value_truncated."""
    big = "A" * (_MAX_ORIGIN_STORAGE_VALUE + 100)
    state = {
        "origins": [
            {"origin": "https://app.example", "localStorage": [{"name": "k", "value": big}]}
        ]
    }
    payload = _backend(monkeypatch, state).storage_origins("s")
    entry = payload["origins"][0]["local"][0]
    assert entry["value_truncated"] is True
    assert len(entry["value"].encode("utf-8")) <= _MAX_ORIGIN_STORAGE_VALUE


def test_storage_origins_caps_entries_per_origin(monkeypatch: Any) -> None:
    """One origin with more entries than the cap reports entries_truncated.

    Measured: entry_count equals the cap, entry_total the real length, and
    entries_truncated true so the origin is not read as complete.
    """
    entries = [
        {"name": f"k{i:05d}", "value": "v"} for i in range(_MAX_STORAGE_ORIGIN_ENTRIES + 1)
    ]
    state = {"origins": [{"origin": "https://app.example", "localStorage": entries}]}
    payload = _backend(monkeypatch, state).storage_origins("s")
    origin = payload["origins"][0]
    assert origin["entry_count"] == _MAX_STORAGE_ORIGIN_ENTRIES
    assert origin["entry_total"] == _MAX_STORAGE_ORIGIN_ENTRIES + 1
    assert origin["entries_truncated"] is True


def test_storage_origins_caps_origin_count_and_paginates(monkeypatch: Any) -> None:
    """Past the origin cap origins_capped is true; paging is honest.

    Measured: with one more origin than the cap, total equals the cap and
    origins_capped is true; a small limit returns a window with has_more.
    """
    origins = [
        {"origin": f"https://o{i:04d}.example", "localStorage": []}
        for i in range(_MAX_STORAGE_ORIGINS + 1)
    ]
    backend = _backend(monkeypatch, {"origins": origins})
    payload = backend.storage_origins("s", offset=0, limit=10)
    assert payload["total"] == _MAX_STORAGE_ORIGINS
    assert payload["origins_capped"] is True
    assert payload["count"] == 10
    assert payload["offset"] == 0
    assert payload["has_more"] is True
    nxt = backend.storage_origins("s", offset=10, limit=10)
    assert nxt["offset"] == 10
    assert nxt["origins"][0]["origin"] != payload["origins"][0]["origin"]


def test_storage_origins_empty_state(monkeypatch: Any) -> None:
    """A context with no stored origins answers with an empty list."""
    payload = _backend(monkeypatch, {"cookies": []}).storage_origins("s")
    assert payload["origins"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["origins_capped"] is False


def test_storage_origins_docstring_names_shape() -> None:
    doc = _tool_docstring("web.storage.origins")
    assert "origins" in doc
    assert "entry_total" in doc
    assert "value_truncated" in doc
    assert "cookies" in doc
