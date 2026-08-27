"""web.network.get must surface the request POST body it captured.

The CDP capture used to keep only the response side, so an agent reversing
an API saw what came back but never what was POSTed. The body is captured on
the request event, returned by web.network.get, and kept out of the lean
web.network.list.
"""

from __future__ import annotations

import ast
from collections import OrderedDict, deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_REQUEST_BODY, WebBackend
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


class _FakeCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        del method, params
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _WireHandle:
    def __init__(self, cdp: _FakeCdp) -> None:
        self.cdp = cdp
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.requests_dropped = 0
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts_dropped = 0
        self.console: deque[dict[str, Any]] = deque(maxlen=2000)
        self.console_dropped = 0


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        del timeout
        return work()


def _wired() -> tuple[WebBackend, _WireHandle, Any]:
    backend = WebBackend()
    cdp = _FakeCdp()
    handle = _WireHandle(cdp)
    backend._wire_events(handle)  # type: ignore[arg-type]
    return backend, handle, cdp.handlers["Network.requestWillBeSent"]


def test_post_body_is_captured_with_its_full_size() -> None:
    _backend, handle, on_request = _wired()
    on_request(
        {
            "requestId": "1",
            "type": "XHR",
            "request": {"url": "https://api/x", "method": "POST", "postData": '{"a":1}'},
        }
    )
    entry = handle.requests["1"]
    assert entry["request_body"] == '{"a":1}'
    assert entry["request_body_size"] == len(b'{"a":1}')
    assert "request_body_truncated" not in entry
    assert "request_body_omitted" not in entry


def test_flagged_but_not_inlined_body_is_reported_omitted_not_absent() -> None:
    _backend, handle, on_request = _wired()
    on_request(
        {
            "requestId": "2",
            "type": "XHR",
            "request": {"url": "https://api/y", "method": "POST", "hasPostData": True},
        }
    )
    entry = handle.requests["2"]
    assert entry["request_body_omitted"] is True
    assert "request_body" not in entry


def test_oversized_body_is_bounded_and_reports_the_true_size() -> None:
    _backend, handle, on_request = _wired()
    big = "x" * (_MAX_REQUEST_BODY + 100)
    on_request(
        {
            "requestId": "3",
            "type": "XHR",
            "request": {"url": "https://api/z", "method": "POST", "postData": big},
        }
    )
    entry = handle.requests["3"]
    assert entry["request_body_truncated"] is True
    assert entry["request_body_size"] == len(big.encode("utf-8"))
    assert len(entry["request_body"].encode("utf-8")) <= _MAX_REQUEST_BODY


def test_a_request_with_no_body_carries_no_request_body_fields() -> None:
    _backend, handle, on_request = _wired()
    on_request(
        {
            "requestId": "4",
            "type": "Document",
            "request": {"url": "https://api/", "method": "GET"},
        }
    )
    entry = handle.requests["4"]
    assert "request_body" not in entry
    assert "request_body_omitted" not in entry


def test_network_list_omits_the_body_but_network_get_returns_it(
    monkeypatch: Any, tmp_path: Path
) -> None:
    backend, handle, on_request = _wired()
    on_request(
        {
            "requestId": "1",
            "type": "XHR",
            "request": {"url": "https://api/x", "method": "POST", "postData": '{"a":1}'},
        }
    )
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Immediate())

    listed = backend.network_list("s", offset=0, limit=100)
    for row in listed["requests"]:
        assert "request_body" not in row
        assert "request_body_size" not in row
        assert "request_body_truncated" not in row
        assert "request_body_omitted" not in row

    got = backend.network_get("s", "1", tmp_path)
    assert got["request_body"] == '{"a":1}'
    assert got["request_body_size"] == len(b'{"a":1}')

    doc = _tool_docstring("web.network.get")
    assert "request_body" in doc
    list_doc = _tool_docstring("web.network.list")
    assert "web.network.get" in list_doc
