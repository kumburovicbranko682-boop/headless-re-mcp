"""web.har.export description must name path and entry_count."""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
from typing import Any

import headless_re_mcp.backends.web.client as web_client
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


class _Handle:
    lock = Lock()
    requests = {
        "1": {
            "method": "GET",
            "url": "https://x",
            "status": 200,
            "mimeType": "text/plain",
            "resourceType": "XHR",
        }
    }


def test_web_har_export_puts_the_file_in_path_not_har(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said a HAR artifact and never named the payload.

    Measured: path and entry_count 1, no har, entries or artifact field.
    Looking for those after a successful call reads as a missing capture.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    payload = backend.har_export("s", tmp_path / "c.har")
    assert "har" not in payload
    assert "entries" not in payload
    assert "artifact" not in payload
    assert payload["entry_count"] == 1
    assert payload["path"].endswith("c.har")
    # A HAR that fit reports nothing trimmed.
    assert payload["truncated"] is False
    assert payload["dropped"] == 0
    doc = _tool_docstring("web.har.export")
    assert "Answers with path" in doc
    assert "entry_count" in doc
    assert "truncated" in doc
    assert "dropped" in doc


class _BigHandle:
    lock = Lock()

    def __init__(self, count: int) -> None:
        self.requests = {
            str(index): {
                "method": "GET",
                "url": "https://x/" + "u" * 500 + str(index),
                "status": 200,
                "mimeType": "text/plain",
                "resourceType": "XHR",
            }
            for index in range(count)
        }


def test_web_har_export_reports_how_many_entries_were_trimmed_to_fit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """When the HAR is trimmed to fit the byte cap, dropped counts the loss.

    truncated alone says a cut happened; dropped says how much of the session
    the file no longer represents, so it is not read as complete.
    """
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", 4096)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _BigHandle(50))
    payload = backend.har_export("s", tmp_path / "c.har")
    assert payload["truncated"] is True
    assert payload["dropped"] > 0
    assert payload["entry_count"] + payload["dropped"] == 50
    assert payload["size"] <= 4096
