"""proxy tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_proxy_flows_puts_the_page_in_flows_with_content_type(
    monkeypatch: Any,
) -> None:
    """The catalog said content type and never named the list field.

    Measured: 25 held, limit 10 -> count 10, total 25, field is flows not
    items or requests, and each row carries content_type with no
    'content type' key. Looking for those after a successful call reads as
    an empty capture, and a full page with no total reads as the whole log.
    """
    recorder = _FlowRecorder(capacity=50)
    for index in range(25):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    payload = backend.flows("s", offset=0, limit=10)
    assert "items" not in payload
    assert "requests" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["flows"]) == 10
    row = payload["flows"][0]
    assert "content type" not in row
    assert row["content_type"] == "text/plain"
    doc = _tool_docstring("proxy.flows")
    assert "Answers with flows" in doc
    assert "content_type" in doc
    assert "total" in doc
