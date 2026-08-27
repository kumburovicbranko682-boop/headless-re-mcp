"""web.dom.query returns selector matches with bounded attributes and text.

The query runs in-page via querySelectorAll; these mock page.evaluate with a
stand-in that honours the maxItems/maxAttrs/maxValueChars the backend passes and
can simulate a malformed selector, so the shaping, caps, and error mapping are
pinned without a live browser.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_DOM_ATTRS,
    _MAX_DOM_ELEMENTS,
    _MAX_DOM_VALUE_BYTES,
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


class _DomRunner:
    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()


class _DomPage:
    """Stand-in for page.evaluate over the querySelectorAll script."""

    def __init__(
        self,
        elements: list[tuple[str, dict[str, str], str]],
        *,
        bad_selector: bool = False,
    ) -> None:
        self._elements = elements
        self._bad = bad_selector

    def evaluate(self, script: str, arg: dict[str, Any]) -> dict[str, Any]:
        del script
        if self._bad:
            return {"error": "Failed to execute 'querySelectorAll': not a valid selector"}
        max_items = int(arg["maxItems"])
        max_attrs = int(arg["maxAttrs"])
        max_chars = int(arg["maxValueChars"])
        out: list[dict[str, Any]] = []
        for tag, attrs, text in self._elements[:max_items]:
            trimmed: dict[str, str] = {}
            count = 0
            names = list(attrs.keys())
            for name in names:
                if count >= max_attrs:
                    break
                trimmed[str(name)] = str(attrs[name])[:max_chars]
                count += 1
            out.append(
                {
                    "tag": tag,
                    "attributes": trimmed,
                    "attrs_truncated": len(names) > count,
                    "text": str(text)[:max_chars],
                }
            )
        return {"elements": out, "total": len(self._elements)}


class _DomHandle:
    def __init__(self, page: _DomPage) -> None:
        self.page = page
        self.runner = _DomRunner()


def _backend_with(monkeypatch: Any, page: _DomPage) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _DomHandle(page))
    return backend


def test_web_dom_query_returns_tag_attrs_and_text(monkeypatch: Any) -> None:
    page = _DomPage(
        [
            ("a", {"href": "https://example.com/login", "class": "btn"}, "Log in"),
            ("a", {"href": "/signup"}, "Sign up"),
        ]
    )
    backend = _backend_with(monkeypatch, page)
    result = backend.dom_query("s", "a[href]")
    assert result["selector"] == "a[href]"
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["has_more"] is False
    first = result["elements"][0]
    assert first["tag"] == "a"
    assert first["attributes"]["href"] == "https://example.com/login"
    assert first["attributes"]["class"] == "btn"
    assert first["attrs_truncated"] is False
    assert first["text"] == "Log in"


def test_web_dom_query_caps_elements_and_reports_total(monkeypatch: Any) -> None:
    elements = [("div", {"id": str(index)}, "") for index in range(120)]
    page = _DomPage(elements)
    backend = _backend_with(monkeypatch, page)
    result = backend.dom_query("s", "div", limit=50)
    assert result["count"] == 50
    assert result["total"] == 120
    assert result["has_more"] is True


def test_web_dom_query_caps_attributes_per_element(monkeypatch: Any) -> None:
    attrs = {f"data-{index}": "v" for index in range(_MAX_DOM_ATTRS + 10)}
    page = _DomPage([("div", attrs, "")])
    backend = _backend_with(monkeypatch, page)
    result = backend.dom_query("s", "div")
    element = result["elements"][0]
    assert len(element["attributes"]) == _MAX_DOM_ATTRS
    assert element["attrs_truncated"] is True


def test_web_dom_query_bounds_a_huge_attribute_value(monkeypatch: Any) -> None:
    """A data-URL-sized attribute value must be bounded before it is returned."""
    big = "d" * (_MAX_DOM_VALUE_BYTES + 5000)
    page = _DomPage([("img", {"src": big}, "")])
    backend = _backend_with(monkeypatch, page)
    result = backend.dom_query("s", "img")
    value = result["elements"][0]["attributes"]["src"]
    assert len(value.encode("utf-8")) <= _MAX_DOM_VALUE_BYTES


def test_web_dom_query_bad_selector_is_invalid_params(monkeypatch: Any) -> None:
    page = _DomPage([], bad_selector=True)
    backend = _backend_with(monkeypatch, page)
    with pytest.raises(WebError) as excinfo:
        backend.dom_query("s", "a[[[")
    assert excinfo.value.code == "invalid_params"


def test_web_dom_query_empty_selector_is_invalid_params(monkeypatch: Any) -> None:
    page = _DomPage([])
    backend = _backend_with(monkeypatch, page)
    with pytest.raises(WebError) as excinfo:
        backend.dom_query("s", "   ")
    assert excinfo.value.code == "invalid_params"


def test_web_dom_query_limit_never_exceeds_the_hard_cap(monkeypatch: Any) -> None:
    """Even an over-large limit is clamped to the element hard cap."""
    elements = [("span", {}, "") for _ in range(_MAX_DOM_ELEMENTS + 50)]
    page = _DomPage(elements)
    backend = _backend_with(monkeypatch, page)
    result = backend.dom_query("s", "span", limit=100_000)
    assert result["count"] == _MAX_DOM_ELEMENTS
    assert result["total"] == _MAX_DOM_ELEMENTS + 50
    assert result["has_more"] is True


def test_web_dom_query_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.dom.query")
    assert doc, "web.dom.query is missing its docstring"
    assert "attributes" in doc
    assert "attrs_truncated" in doc
    assert "has_more" in doc
    assert "invalid_params" in doc
