"""web tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

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


class _FakeHandle:
    def __init__(self, count: int) -> None:
        self.lock = Lock()
        self.console = deque({"text": str(index)} for index in range(count))
        self.requests = {
            str(index): {
                "requestId": str(index),
                "url": f"https://example/{index}",
                "method": "GET",
                "resourceType": "XHR",
                "status": 200,
                "mimeType": "application/json",
            }
            for index in range(count)
        }


def test_web_console_puts_messages_in_console_and_says_when_it_stopped(
    monkeypatch: Any,
) -> None:
    """The catalog said messages and never named the payload.

    Measured: 25 held, limit 10 -> count 10, has_more True, field is console
    not messages or logs. Looking for messages after a successful call reads
    as an empty console, and a full page with no has_more reads as the buffer.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(25))
    payload = backend.console("s", limit=10)
    assert "messages" not in payload
    assert "logs" not in payload
    assert payload["count"] == 10
    assert len(payload["console"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("web.console")
    assert "Answers with console" in doc
    assert "has_more" in doc


def test_web_network_list_puts_the_page_in_requests_not_type(
    monkeypatch: Any,
) -> None:
    """The catalog said type and never named the list field.

    Measured: 25 held, limit 10 -> count 10, total 25, field is requests
    not items or network, and each row carries resourceType with no type
    key. Looking for type or network after a successful call reads as an
    empty capture, and a full page with no total reads as the whole log.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeHandle(25))
    payload = backend.network_list("s", offset=0, limit=10)
    assert "network" not in payload
    assert "items" not in payload
    assert "has_more" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["offset"] == 0
    assert len(payload["requests"]) == 10
    row = payload["requests"][0]
    assert "type" not in row
    assert row["resourceType"] == "XHR"
    doc = _tool_docstring("web.network.list")
    assert "Answers with requests" in doc
    assert "resourceType" in doc
    assert "total" in doc
