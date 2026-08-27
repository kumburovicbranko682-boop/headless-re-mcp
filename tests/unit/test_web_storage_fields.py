"""web.storage must read localStorage/sessionStorage honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_VALUE_BYTES,
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


class _Page:
    url = "https://app.example/dashboard"

    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result

    def evaluate(self, script: str, arg: Any) -> dict[str, Any]:
        del script, arg
        return self._result


def _backend(monkeypatch: Any, result: dict[str, Any]) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page(result)))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_storage_returns_both_stores_with_totals(monkeypatch: Any) -> None:
    """local and session storage come back as key/value lists with totals.

    A JWT in localStorage is the token web triage wants after cookies. Both
    stores are reported separately, each with its total so a capped list is
    not read as the whole store.
    """
    result = {
        "local": {
            "entries": [
                {"key": "jwt", "value": "eyJhbGciOi.J", "truncated": False},
                {"key": "flags", "value": '{"beta":true}', "truncated": False},
            ],
            "total": 2,
        },
        "session": {"entries": [{"key": "nonce", "value": "abc", "truncated": False}], "total": 1},
    }
    backend = _backend(monkeypatch, result)
    payload = backend.storage("s")
    assert payload["url"] == "https://app.example/dashboard"
    assert {e["key"] for e in payload["local_storage"]} == {"jwt", "flags"}
    assert payload["local_storage_total"] == 2
    assert payload["local_storage_has_more"] is False
    assert payload["session_storage"] == [{"key": "nonce", "value": "abc"}]
    assert payload["session_storage_total"] == 1
    assert "storage" not in payload
    assert "items" not in payload
    doc = _tool_docstring("web.storage")
    assert "local_storage" in doc
    assert "session_storage" in doc


def test_web_storage_flags_has_more_when_the_store_was_capped(monkeypatch: Any) -> None:
    """A store with more items than returned trips its has_more.

    total says 900 but only two entries came back (a capped dump), so
    local_storage_has_more must be True -- the page is not read as tiny.
    """
    result = {
        "local": {
            "entries": [
                {"key": "a", "value": "1", "truncated": False},
                {"key": "b", "value": "2", "truncated": False},
            ],
            "total": 900,
        },
        "session": {"entries": [], "total": 0},
    }
    backend = _backend(monkeypatch, result)
    payload = backend.storage("s")
    assert payload["local_storage_has_more"] is True
    assert payload["session_storage_has_more"] is False


def test_web_storage_bounds_a_huge_value_and_flags_it(monkeypatch: Any) -> None:
    """An oversized value is cut server-side and marked value_truncated."""
    huge = "A" * (_MAX_STORAGE_VALUE_BYTES + 50)
    result = {
        "local": {
            "entries": [{"key": "blob", "value": huge, "truncated": False}],
            "total": 1,
        },
        "session": {"entries": [], "total": 0},
    }
    backend = _backend(monkeypatch, result)
    payload = backend.storage("s")
    entry = payload["local_storage"][0]
    assert len(entry["value"].encode("utf-8")) <= _MAX_STORAGE_VALUE_BYTES
    assert entry["value_truncated"] is True


def test_web_storage_marks_an_unreadable_store_unavailable_not_empty(monkeypatch: Any) -> None:
    """A store that threw is unavailable, distinct from an empty store.

    The page's sessionStorage raised (opaque origin), so it comes back
    flagged unavailable rather than as an empty list an analyst would read as
    "nothing stored".
    """
    result = {
        "local": {"entries": [], "total": 0},
        "session": {"entries": [], "total": 0, "unavailable": True},
    }
    backend = _backend(monkeypatch, result)
    payload = backend.storage("s")
    assert payload["session_storage_unavailable"] is True
    assert "local_storage_unavailable" not in payload
