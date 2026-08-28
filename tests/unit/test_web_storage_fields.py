"""web.storage reads both Web Storage areas, bounded and defensively.

Driven through the same _get/_runner seam the other web field tests use, with a
fake page whose evaluate() returns the shape the in-page script produces. No
real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_VALUE_CHARS,
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
    url = "https://example/app"

    def __init__(self, result: dict[str, Any]) -> None:
        self._result = result

    def evaluate(self, script: str, cfg: dict[str, Any]) -> dict[str, Any]:
        del script, cfg
        return self._result


def _backend_with(monkeypatch: Any, result: dict[str, Any]) -> WebBackend:
    backend = WebBackend()
    page = _Page(result)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_storage_reads_both_areas(monkeypatch: Any) -> None:
    result = {
        "origin": "https://example",
        "local": {
            "entries": [
                {"key": "token", "value": "abc", "value_truncated": False},
                {"key": "flags", "value": "x", "value_truncated": False},
            ],
            "total": 2,
            "error": None,
        },
        "session": {
            "entries": [{"key": "csrf", "value": "z", "value_truncated": False}],
            "total": 1,
            "error": None,
        },
    }
    payload = _backend_with(monkeypatch, result).storage("s")

    assert payload["url"] == "https://example/app"
    assert payload["origin"] == "https://example"
    assert payload["local_storage_count"] == 2
    assert payload["local_storage_truncated"] is False
    assert payload["session_storage_count"] == 1
    keys = {row["key"] for row in payload["local_storage"]}
    assert keys == {"token", "flags"}
    assert "local_storage_error" not in payload
    assert "session_storage_error" not in payload


def test_storage_flags_a_capped_key_list(monkeypatch: Any) -> None:
    """total above the returned entry count -> the key list was capped."""
    result = {
        "origin": "https://example",
        "local": {
            "entries": [{"key": "a", "value": "1", "value_truncated": False}],
            "total": 900,
            "error": None,
        },
        "session": {"entries": [], "total": 0, "error": None},
    }
    payload = _backend_with(monkeypatch, result).storage("s")
    assert payload["local_storage_count"] == 1
    assert payload["local_storage_truncated"] is True
    assert payload["session_storage_truncated"] is False


def test_storage_clips_an_oversized_value(monkeypatch: Any) -> None:
    """A value beyond the cap is clipped and flagged even if the page lied."""
    result = {
        "origin": "https://example",
        "local": {
            "entries": [
                {
                    "key": "blob",
                    "value": "y" * (_MAX_STORAGE_VALUE_CHARS + 100),
                    "value_truncated": False,
                }
            ],
            "total": 1,
            "error": None,
        },
        "session": {"entries": [], "total": 0, "error": None},
    }
    payload = _backend_with(monkeypatch, result).storage("s")
    row = payload["local_storage"][0]
    assert len(row["value"]) == _MAX_STORAGE_VALUE_CHARS
    assert row["value_truncated"] is True


def test_storage_surfaces_a_per_area_error(monkeypatch: Any) -> None:
    """An opaque origin makes one store throw; the other still returns."""
    result = {
        "origin": "",
        "local": {"entries": [], "total": 0, "error": "SecurityError"},
        "session": {
            "entries": [{"key": "ok", "value": "1", "value_truncated": False}],
            "total": 1,
            "error": None,
        },
    }
    payload = _backend_with(monkeypatch, result).storage("s")
    assert payload["local_storage_error"] == "SecurityError"
    assert payload["local_storage_count"] == 0
    assert payload["session_storage_count"] == 1
    assert "session_storage_error" not in payload


def test_web_storage_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.storage")
    assert "local_storage" in doc
    assert "session_storage" in doc
    assert "value_truncated" in doc
    assert "origin" in doc
