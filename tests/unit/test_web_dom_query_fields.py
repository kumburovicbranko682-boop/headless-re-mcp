"""web.dom.query pulls selector-matched elements out of the live DOM, bounded.

Driven through the _get/_runner seam with a fake page whose evaluate() returns
the shape the in-page querySelectorAll script produces.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError, _fold_dom_query
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
    def __init__(self, result: Any) -> None:
        self._result = result

    def evaluate(self, script: str, cfg: dict[str, Any]) -> Any:
        del script, cfg
        return self._result


def _backend_with(monkeypatch: Any, result: Any) -> WebBackend:
    backend = WebBackend()
    page = _Page(result)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _dump() -> dict[str, Any]:
    return {
        "total": 2,
        "elements": [
            {
                "tag": "input",
                "text": "",
                "attributes": {"type": "password", "name": "pw"},
                "attr_count": 2,
                "html": '<input type="password" name="pw">',
            },
            {
                "tag": "input",
                "text": "",
                "attributes": {"type": "hidden", "name": "csrf", "value": "tok"},
                "attr_count": 3,
                "html": '<input type="hidden" name="csrf" value="tok">',
            },
        ],
    }


def test_dom_query_folds_matched_elements() -> None:
    payload = _fold_dom_query(_dump(), "form input")
    assert payload["selector"] == "form input"
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["truncated"] is False
    first = payload["elements"][0]
    assert first["tag"] == "input"
    assert first["attributes"]["type"] == "password"
    assert first["attr_count"] == 2


def test_dom_query_reports_truncation_from_total() -> None:
    raw = _dump()
    raw["total"] = 40  # more matched on the page than were returned
    payload = _fold_dom_query(raw, "div")
    assert payload["count"] == 2
    assert payload["total"] == 40
    assert payload["truncated"] is True


def test_dom_query_tolerates_a_missing_elements_key() -> None:
    payload = _fold_dom_query({"total": 0}, ".none")
    assert payload["count"] == 0
    assert payload["elements"] == []


def test_dom_query_runs_through_the_backend_seam(monkeypatch: Any) -> None:
    payload = _backend_with(monkeypatch, _dump()).dom_query("s", "form input")
    assert payload["count"] == 2
    assert payload["elements"][1]["attributes"]["name"] == "csrf"


def test_dom_query_rejects_an_empty_selector(monkeypatch: Any) -> None:
    backend = _backend_with(monkeypatch, _dump())
    with pytest.raises(WebError) as caught:
        backend.dom_query("s", "   ")
    assert caught.value.code == "invalid_params"


def test_dom_query_maps_an_invalid_selector_to_invalid_params(monkeypatch: Any) -> None:
    # The in-page script returns {error: ...} for a selector querySelectorAll rejects.
    backend = _backend_with(monkeypatch, {"error": "'::' is not a valid selector"})
    with pytest.raises(WebError) as caught:
        backend.dom_query("s", "::")
    assert caught.value.code == "invalid_params"


def test_web_dom_query_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.dom.query")
    assert "selector" in doc
    assert "attributes" in doc
    assert "truncated" in doc
    assert "attr_count" in doc
