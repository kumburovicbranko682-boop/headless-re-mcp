"""web.open must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.web.client import WebBackend
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


def test_web_open_puts_the_result_in_opened_url_title_headless() -> None:
    """The catalog said launch and never named the payload.

    Measured against WebBackend.open: success is opened, url, title and
    headless. There is no session, browser, ok or page field. Looking for
    those after a successful open reads as a browser that never started.
    """
    source = Path(WebBackend.open.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def open(")
    chunk = source[start : source.index("def _wire_events", start)]
    marker = chunk.rindex("summary = {")
    returned = chunk[marker : chunk.index("}", marker) + 1]
    assert '"opened"' in returned
    assert '"url"' in returned
    assert '"title"' in returned
    assert '"headless"' in returned
    assert '"session"' not in returned
    assert '"browser"' not in returned
    assert '"ok"' not in returned
    assert '"page"' not in returned
    doc = _tool_docstring("web.open")
    assert "Answers with opened" in doc
    assert "url" in doc
    assert "title" in doc
    assert "headless" in doc
    assert "status" in doc


def test_web_open_threads_the_landing_http_status_from_goto() -> None:
    """An open whose landing page 404s must show it, like web.navigate does.

    open() runs the first page.goto itself and used to drop its response, so a
    4xx/5xx landing page read as a clean open. Pinned at the source (open() cannot
    be instantiated without a real browser): the initial goto's response is kept
    and its status added to the summary when present.
    """
    source = Path(WebBackend.open.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def open(")
    chunk = source[start : source.index("def _wire_events", start)]
    assert "response = page.goto(" in chunk
    assert 'getattr(response, "status"' in chunk
    assert 'summary["status"] = status' in chunk
