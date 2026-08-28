"""web.storage must read Web Storage, stay bounded, and name its fields.

The Web Storage companion to web.cookies: SPAs keep JWT/refresh tokens and app
config in localStorage/sessionStorage, which no Set-Cookie capture or
document.cookie read reaches. These cover the area selection, the in-browser
bounds, key filtering, and the opaque-origin (data:/about:blank) case.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_ITEMS,
    _MAX_STORAGE_VALUE,
    WebBackend,
    WebError,
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
    """A page whose evaluate() imitates the fixed storage snippet in JS.

    Honors the area choice and the in-browser item/value caps the real snippet
    applies, so the backend's own bounds and shaping are what gets exercised.
    """

    def __init__(
        self,
        local: dict[str, str] | None = None,
        session: dict[str, str] | None = None,
        *,
        origin: str = "https://app.example.com",
        unavailable: bool = False,
    ) -> None:
        self._local = local or {}
        self._session = session or {}
        self._origin = origin
        self._unavailable = unavailable

    def evaluate(self, expression: str, arg: dict[str, Any]) -> dict[str, Any]:
        del expression
        if self._unavailable:
            return {"unavailable": True, "origin": ""}
        source = self._session if arg["area"] == "session" else self._local
        max_items = int(arg["maxItems"])
        max_value = int(arg["maxValue"])
        items = []
        over = False
        for key, value in source.items():
            if len(items) >= max_items:
                over = True
                break
            clipped = len(value) > max_value
            items.append(
                {
                    "key": key,
                    "value": value[:max_value] if clipped else value,
                    "value_truncated": clipped,
                }
            )
        return {"origin": self._origin, "items": items, "total": len(source), "over": over}


def _backend(page: _Page, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    handle = SimpleNamespace(page=page)
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_storage_reads_local_by_default_and_names_its_fields(monkeypatch: Any) -> None:
    """kind defaults to local; the payload is storage/kind/origin, not cookies."""
    page = _Page(local={"jwt": "header.payload.sig", "flag": "on"})
    out = _backend(page, monkeypatch).storage("s")
    assert out["kind"] == "local"
    assert out["origin"] == "https://app.example.com"
    assert out["count"] == 2
    assert out["total"] == 2
    assert out["has_more"] is False
    assert out["collection_truncated"] is False
    by_key = {row["key"]: row["value"] for row in out["storage"]}
    assert by_key == {"jwt": "header.payload.sig", "flag": "on"}
    assert "cookies" not in out
    doc = _tool_docstring("web.storage")
    assert "Answers with storage" in doc
    assert "localStorage" in doc
    assert "read-only" in doc


def test_web_storage_session_area_is_selectable(monkeypatch: Any) -> None:
    """kind=session reads the per-tab store, not localStorage."""
    page = _Page(local={"a": "1"}, session={"tab": "xyz"})
    out = _backend(page, monkeypatch).storage("s", kind="session")
    assert out["kind"] == "session"
    assert {row["key"] for row in out["storage"]} == {"tab"}


def test_web_storage_rejects_an_unknown_area(monkeypatch: Any) -> None:
    page = _Page(local={"a": "1"})
    with pytest.raises(WebError) as info:
        _backend(page, monkeypatch).storage("s", kind="cookies")
    assert info.value.code == "invalid_params"


def test_web_storage_clips_a_huge_value_and_marks_it(monkeypatch: Any) -> None:
    page = _Page(local={"blob": "A" * (_MAX_STORAGE_VALUE + 500)})
    out = _backend(page, monkeypatch).storage("s")
    row = out["storage"][0]
    assert len(row["value"].encode()) <= _MAX_STORAGE_VALUE
    assert row["value_truncated"] is True


def test_web_storage_caps_the_collected_universe(monkeypatch: Any) -> None:
    page = _Page(local={f"k{index}": "v" for index in range(_MAX_STORAGE_ITEMS + 5)})
    out = _backend(page, monkeypatch).storage("s", limit=1000)
    assert out["total"] == _MAX_STORAGE_ITEMS
    assert out["collection_truncated"] is True
    assert out["count"] == _MAX_STORAGE_ITEMS


def test_web_storage_filters_by_key_before_paging(monkeypatch: Any) -> None:
    page = _Page(
        local={"authToken": "1", "theme": "dark", "AUTH_refresh": "2"}
    )
    out = _backend(page, monkeypatch).storage("s", key_filter="auth")
    assert {row["key"] for row in out["storage"]} == {"authToken", "AUTH_refresh"}
    assert out["total"] == 2


def test_web_storage_reports_invalid_state_for_an_opaque_origin(monkeypatch: Any) -> None:
    """data:/about:blank have no storage: say so rather than an empty jar."""
    page = _Page(unavailable=True)
    with pytest.raises(WebError) as info:
        _backend(page, monkeypatch).storage("s")
    assert info.value.code == "invalid_state"


def test_web_storage_is_classified_read_only() -> None:
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "web.storage" in _READ_ONLY_NAMES
