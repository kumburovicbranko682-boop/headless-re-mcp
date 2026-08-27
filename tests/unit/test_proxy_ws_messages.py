"""Proxy WebSocket surfacing: flows flag WS, flow.get returns the frames.

mitmproxy accumulates WebSocket frames on the same flow object the recorder
retains, but the proxy line never surfaced them -- a captured socket looked like
a lone 101 handshake with no traffic. These tests pin that proxy.flows marks a
WebSocket flow with a running message count and proxy.flow.get returns the
frames, normalised (direction, text preview, base64 for binary) and bounded the
same way the browser capture is.
"""

from __future__ import annotations

import ast
import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
    _MAX_WS_PAYLOAD,
    ProxyBackend,
    ProxyError,
    _FlowRecorder,
)
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


def _ws_flow(messages: list[Any], *, flow_id: str = "w1", closed: bool = True) -> Any:
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://x/ws",
        host="x",
        headers={"upgrade": "websocket"},
    )
    response = SimpleNamespace(status_code=101, headers={}, raw_content=b"")
    websocket = SimpleNamespace(
        messages=messages,
        timestamp_end=4.0 if closed else None,
        close_code=1000 if closed else None,
    )
    return SimpleNamespace(id=flow_id, request=request, response=response, websocket=websocket)


def _msg(*, from_client: bool, content: bytes, opcode: int, ts: float) -> Any:
    return SimpleNamespace(from_client=from_client, content=content, type=opcode, timestamp=ts)


def test_flows_flag_a_websocket_flow_with_a_message_count(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=8)
    messages = [
        _msg(from_client=True, content=b"hello", opcode=1, ts=1.0),
        _msg(from_client=False, content=b"world", opcode=1, ts=2.0),
    ]
    flow = _ws_flow(messages)
    recorder.response(flow)
    recorder.websocket_message(flow)

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    listing = backend.flows("s")
    row = next(r for r in listing["flows"] if r["id"] == "w1")
    assert row["status"] == 101
    assert row["websocket"] is True
    assert row["ws_messages"] == 2


def test_flow_get_returns_the_websocket_frames(tmp_path: Path, monkeypatch: Any) -> None:
    messages = [
        _msg(from_client=True, content=b"hello", opcode=1, ts=1.0),
        _msg(from_client=False, content=b"world", opcode=1, ts=2.0),
        _msg(from_client=False, content=b"\x00\x01\x02\xff", opcode=2, ts=3.0),
    ]
    flow = _ws_flow(messages)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    payload = backend.flow_get("s", "w1", tmp_path)

    assert "websocket" in payload
    ws = payload["websocket"]
    assert ws["total"] == 3
    assert ws["count"] == 3
    assert ws["closed"] is True
    assert ws["close_code"] == 1000

    frames = ws["messages"]
    sent = next(f for f in frames if f["direction"] == "sent")
    assert sent["type"] == "text"
    assert sent["payload"] == "hello"

    recv_text = next(f for f in frames if f["direction"] == "received" and f["type"] == "text")
    assert recv_text["payload"] == "world"

    binary = next(f for f in frames if f["type"] == "binary")
    assert binary["direction"] == "received"
    # A binary frame's bytes survive as base64, not a lossy text rendering.
    assert base64.b64decode(binary["payload"]) == b"\x00\x01\x02\xff"
    assert binary["payload_len"] == 4


def test_flow_get_bounds_a_giant_binary_frame(tmp_path: Path, monkeypatch: Any) -> None:
    blob = bytes((i * 7) & 0xFF for i in range(_MAX_WS_PAYLOAD + 500))
    flow = _ws_flow([_msg(from_client=False, content=blob, opcode=2, ts=1.0)])

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    frame = backend.flow_get("s", "w1", tmp_path)["websocket"]["messages"][0]
    assert frame["payload_truncated"] is True
    # The preview holds at most the cap; payload_len keeps the true byte count.
    assert len(base64.b64decode(frame["payload"])) == _MAX_WS_PAYLOAD
    assert frame["payload_len"] == _MAX_WS_PAYLOAD + 500


def test_plain_http_flow_has_no_websocket_key(tmp_path: Path, monkeypatch: Any) -> None:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers={"accept": "*/*"})
    response = SimpleNamespace(
        status_code=200, headers={"content-type": "text/plain"}, raw_content=b"ok"
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    payload = backend.flow_get("s", "f1", tmp_path)
    assert "websocket" not in payload


def test_ws_frame_get_rejects_unknown_flow(monkeypatch: Any) -> None:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return None

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    with pytest.raises(ProxyError) as excinfo:
        backend.flow_get("s", "missing", Path("/tmp"))
    assert excinfo.value.code == "not_found"


def test_proxy_ws_descriptions_name_the_frame_fields() -> None:
    flows = _tool_docstring("proxy.flows")
    assert "websocket" in flows
    assert "ws_messages" in flows

    flow_get = _tool_docstring("proxy.flow.get")
    assert "websocket" in flow_get
    assert "payload_truncated" in flow_get
    assert "base64" in flow_get
