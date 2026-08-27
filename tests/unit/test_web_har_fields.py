"""web.har.export description must name path and entry_count."""

from __future__ import annotations

import ast
import json
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


class _Handle:
    lock = Lock()
    requests = {
        "1": {
            "method": "GET",
            "url": "https://x/api?a=1&b=2",
            "status": 200,
            "mimeType": "text/plain",
            "resourceType": "XHR",
            "request_headers": {"Authorization": "Bearer t"},
            "response_headers": {"Content-Type": "text/plain", "Set-Cookie": "s=1"},
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
    doc = _tool_docstring("web.har.export")
    assert "Answers with path" in doc
    assert "entry_count" in doc


def test_web_har_export_is_conformant_and_carries_headers(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The HAR must be valid HAR 1.2 and carry the captured headers.

    Entries that omit startedDateTime/timings/cookies/headers/queryString/cache
    are rejected by real HAR viewers. Write the file, load it back, and assert
    the required entry fields are present and that the captured request/response
    headers land in HAR's name/value arrays with the query string parsed out.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _Handle())
    out = tmp_path / "c.har"
    backend.har_export("s", out)
    log = json.loads(out.read_text(encoding="utf-8"))["log"]
    assert log["version"] == "1.2"
    entry = log["entries"][0]
    for field in ("startedDateTime", "time", "request", "response", "cache", "timings"):
        assert field in entry, field
    for field in ("send", "wait", "receive"):
        assert field in entry["timings"], field
    req, resp = entry["request"], entry["response"]
    for field in ("method", "url", "httpVersion", "cookies", "headers", "queryString"):
        assert field in req, field
    for field in ("status", "statusText", "httpVersion", "cookies", "headers", "content"):
        assert field in resp, field
    req_headers = {h["name"]: h["value"] for h in req["headers"]}
    resp_headers = {h["name"]: h["value"] for h in resp["headers"]}
    assert req_headers["Authorization"] == "Bearer t"
    assert resp_headers["Set-Cookie"] == "s=1"
    query = {q["name"]: q["value"] for q in req["queryString"]}
    assert query == {"a": "1", "b": "2"}
