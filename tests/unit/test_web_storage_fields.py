"""web.storage must read local/session storage, cap big values, and page.

Front-ends stash tokens and config in Web Storage, which no cookie or network
reader shows. These pin that web.storage reads the chosen store through the
page context, caps an oversized value while keeping its true length, discloses
a store larger than the read guard, and pages like the other capture readers.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
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


class _Page:
    def __init__(self, result: Any, *, raise_on_eval: bool = False) -> None:
        self._result = result
        self._raise = raise_on_eval
        self.calls: list[list[Any]] = []

    def evaluate(self, script: str, arg: Any) -> Any:
        del script
        self.calls.append(arg)
        if self._raise:
            raise RuntimeError("storage blocked")
        return self._result


class _Handle:
    def __init__(self, page: _Page) -> None:
        self.page = page


class _Runner:
    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return fn()


def _backend_for(handle: _Handle, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Runner())
    return backend


def test_local_storage_entries_are_sorted_and_typed(monkeypatch: Any) -> None:
    page = _Page(
        {
            "total": 2,
            "entries": [["token", "jwt-abc", 7], ["cfg", '{"a":1}', 7]],
            "capped": False,
        }
    )
    backend = _backend_for(_Handle(page), monkeypatch)
    result = backend.storage("s", which="local")

    assert result["which"] == "local"
    assert result["total"] == 2
    # Sorted by key: cfg before token.
    assert [e["key"] for e in result["entries"]] == ["cfg", "token"]
    tok = next(e for e in result["entries"] if e["key"] == "token")
    assert tok["value"] == "jwt-abc"
    assert tok["value_len"] == 7
    assert tok["value_truncated"] is False
    assert result["scan_capped"] is False
    # The store the page read was the local one (first evaluate arg element).
    assert page.calls[0][0] == "local"


def test_session_store_is_selected(monkeypatch: Any) -> None:
    page = _Page({"total": 1, "entries": [["sess", "xyz", 3]], "capped": False})
    backend = _backend_for(_Handle(page), monkeypatch)
    result = backend.storage("s", which="session")

    assert result["which"] == "session"
    assert page.calls[0][0] == "session"
    assert result["entries"][0]["key"] == "sess"


def test_an_oversized_value_is_cut_but_its_true_length_kept(monkeypatch: Any) -> None:
    # The page already cut the preview to the cap; value_len keeps the real size.
    cut = "z" * _MAX_STORAGE_VALUE
    page = _Page(
        {"total": 1, "entries": [["blob", cut, _MAX_STORAGE_VALUE + 500]], "capped": False}
    )
    backend = _backend_for(_Handle(page), monkeypatch)
    result = backend.storage("s")
    entry = result["entries"][0]

    assert len(entry["value"]) == _MAX_STORAGE_VALUE
    assert entry["value_len"] == _MAX_STORAGE_VALUE + 500
    assert entry["value_truncated"] is True


def test_a_store_past_the_read_guard_sets_scan_capped(monkeypatch: Any) -> None:
    page = _Page({"total": 99_999, "entries": [["k", "v", 1]], "capped": True})
    backend = _backend_for(_Handle(page), monkeypatch)
    result = backend.storage("s")

    # total is the true store size; scan_capped says not all of it was pulled.
    assert result["total"] == 99_999
    assert result["scan_capped"] is True


def test_entries_paginate(monkeypatch: Any) -> None:
    entries = [[f"k{i:02d}", str(i), 1] for i in range(5)]
    page = _Page({"total": 5, "entries": entries, "capped": False})
    backend = _backend_for(_Handle(page), monkeypatch)

    first = backend.storage("s", offset=1, limit=2)
    assert first["offset"] == 1
    assert first["count"] == 2
    assert first["has_more"] is True

    tail = backend.storage("s", offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_an_unknown_store_is_rejected(monkeypatch: Any) -> None:
    backend = _backend_for(_Handle(_Page({})), monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.storage("s", which="cache")
    assert excinfo.value.code == "invalid_params"


def test_storage_faults_soft_when_the_page_blocks_it(monkeypatch: Any) -> None:
    backend = _backend_for(_Handle(_Page({}, raise_on_eval=True)), monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.storage("s")
    assert excinfo.value.code == "backend_error"


def test_storage_docstring_names_the_stores_and_fields() -> None:
    doc = " ".join(_tool_docstring("web.storage").split())
    assert "localStorage" in doc
    assert "sessionStorage" in doc
    assert "value_truncated" in doc
    assert "scan_capped" in doc
    assert "has_more" in doc
