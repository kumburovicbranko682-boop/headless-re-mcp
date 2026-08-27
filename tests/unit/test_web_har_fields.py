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
    # A capture small enough to fit is not marked trimmed, and size is the
    # written byte count so a caller can see it before opening the file.
    assert payload["truncated"] is False
    assert payload["size"] > 0
    doc = _tool_docstring("web.har.export")
    assert "Answers with path" in doc
    assert "entry_count" in doc
    assert "truncated" in doc
    assert "size" in doc
    assert "artifact_id" in doc
    assert "artifact_error" in doc


class _ManyHandle:
    def __init__(self, count: int) -> None:
        self.lock = Lock()
        self.requests = {
            str(index): {
                "method": "GET",
                "url": f"https://example.test/resource/{index}",
                "status": 200,
                "mimeType": "application/json",
                "resourceType": "XHR",
            }
            for index in range(count)
        }


def test_web_har_export_marks_truncated_when_it_trims_to_fit_the_cap(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """entry_count alone hides that the HAR dropped its oldest entries.

    With the cap shrunk below the full document, the export trims the oldest
    entries to fit and sets truncated, so entry_count reads as a subset of
    what was captured rather than the whole log. size stays within the cap.
    """
    cap = 1000
    monkeypatch.setattr(web_client, "UNREGISTERED_CAPTURE_MAX_BYTES", cap)
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _ManyHandle(40))
    payload = backend.har_export("s", tmp_path / "big.har")
    assert payload["truncated"] is True
    assert payload["size"] <= cap
    assert 0 < payload["entry_count"] < 40
