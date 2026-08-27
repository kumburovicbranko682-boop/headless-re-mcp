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
    _OMITTED_BODY,
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

        def ws_dropped(self, flow_id: str) -> int:
            return 0

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

        def ws_dropped(self, flow_id: str) -> int:
            return 0

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

        def ws_dropped(self, flow_id: str) -> int:
            return 0

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


def test_ws_frames_pages_the_full_conversation(monkeypatch: Any) -> None:
    messages = [
        _msg(from_client=True, content=str(i).encode(), opcode=1, ts=float(i)) for i in range(5)
    ]
    flow = _ws_flow(messages)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

        def ws_dropped(self, flow_id: str) -> int:
            return 0

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))

    first = backend.ws_frames("s", "w1", offset=1, limit=2)
    assert first["flow_id"] == "w1"
    assert first["url"] == "http://x/ws"
    assert first["total"] == 5
    assert first["offset"] == 1
    assert first["count"] == 2
    assert first["has_more"] is True
    assert first["closed"] is True
    assert first["close_code"] == 1000
    assert [f["payload"] for f in first["frames"]] == ["1", "2"]

    tail = backend.ws_frames("s", "w1", offset=3, limit=10)
    assert tail["offset"] == 3
    assert tail["count"] == 2
    assert tail["has_more"] is False
    assert [f["payload"] for f in tail["frames"]] == ["3", "4"]


def test_ws_frames_rejects_a_plain_http_flow(monkeypatch: Any) -> None:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers={})
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"ok")
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

        def ws_dropped(self, flow_id: str) -> int:
            return 0

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    with pytest.raises(ProxyError) as excinfo:
        backend.ws_frames("s", "f1")
    assert excinfo.value.code == "invalid_state"


def test_ws_frames_rejects_unknown_flow(monkeypatch: Any) -> None:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return None

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    with pytest.raises(ProxyError) as excinfo:
        backend.ws_frames("s", "missing")
    assert excinfo.value.code == "not_found"


def test_ws_frames_reports_a_dropped_flow_as_too_large(monkeypatch: Any) -> None:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return _OMITTED_BODY

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    with pytest.raises(ProxyError) as excinfo:
        backend.ws_frames("s", "w1")
    assert excinfo.value.code == "too_large"


def test_websocket_retention_is_bounded_by_frame_count(monkeypatch: Any) -> None:
    import headless_re_mcp.backends.proxy.client as pc

    monkeypatch.setattr(pc, "_MAX_WS_RETAINED", 5)
    recorder = _FlowRecorder(capacity=8)
    messages: list[Any] = []
    flow = _ws_flow(messages, closed=False)
    recorder.response(flow)
    for i in range(20):
        messages.append(_msg(from_client=True, content=str(i).encode(), opcode=1, ts=float(i)))
        recorder.websocket_message(flow)

    # mitmproxy's own list is trimmed in place to the cap: the oldest frames are
    # gone, so a socket cannot grow the flow object without bound.
    assert len(messages) == 5
    assert [m.content for m in messages] == [str(i).encode() for i in range(15, 20)]
    assert recorder.ws_dropped("w1") == 15

    row = next(r for r in recorder.snapshot() if r["id"] == "w1")
    assert row["websocket"] is True
    assert row["ws_messages"] == 5
    assert row["ws_dropped"] == 15


def test_websocket_retention_is_bounded_by_total_bytes(monkeypatch: Any) -> None:
    import headless_re_mcp.backends.proxy.client as pc

    monkeypatch.setattr(pc, "_MAX_WS_RETAINED_BYTES", 4 * 1024)
    recorder = _FlowRecorder(capacity=8)
    messages: list[Any] = []
    flow = _ws_flow(messages, closed=False)
    recorder.response(flow)
    for i in range(10):
        messages.append(_msg(from_client=False, content=b"x" * 1024, opcode=2, ts=float(i)))
        recorder.websocket_message(flow)

    # A 4 KiB budget holds at most four 1 KiB frames; the rest are evicted.
    assert len(messages) == 4
    assert sum(len(m.content) for m in messages) <= 4 * 1024
    assert recorder.ws_dropped("w1") == 6


def test_websocket_retention_keeps_a_lone_oversized_frame(monkeypatch: Any) -> None:
    import headless_re_mcp.backends.proxy.client as pc

    monkeypatch.setattr(pc, "_MAX_WS_RETAINED_BYTES", 1024)
    recorder = _FlowRecorder(capacity=8)
    messages: list[Any] = []
    flow = _ws_flow(messages, closed=False)
    recorder.response(flow)
    messages.append(_msg(from_client=False, content=b"y" * 8192, opcode=2, ts=1.0))
    recorder.websocket_message(flow)

    # A single frame over the byte cap is kept -- we cannot shrink it, and
    # dropping it would erase the only content the socket carried.
    assert len(messages) == 1
    assert recorder.ws_dropped("w1") == 0


def test_flow_get_and_ws_frames_disclose_dropped_frames(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import headless_re_mcp.backends.proxy.client as pc

    monkeypatch.setattr(pc, "_MAX_WS_RETAINED", 3)
    recorder = _FlowRecorder(capacity=8)
    messages: list[Any] = []
    flow = _ws_flow(messages, closed=True)
    recorder.response(flow)
    for i in range(8):
        messages.append(_msg(from_client=True, content=str(i).encode(), opcode=1, ts=float(i)))
        recorder.websocket_message(flow)

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))

    detail = backend.flow_get("s", "w1", tmp_path)
    assert detail["websocket"]["total"] == 3
    assert detail["websocket"]["dropped"] == 5

    page = backend.ws_frames("s", "w1")
    assert page["total"] == 3
    assert page["dropped"] == 5
    assert [f["payload"] for f in page["frames"]] == ["5", "6", "7"]


def test_proxy_ws_descriptions_name_the_frame_fields() -> None:
    flows = _tool_docstring("proxy.flows")
    assert "websocket" in flows
    assert "ws_messages" in flows
    assert "ws_dropped" in flows

    flow_get = _tool_docstring("proxy.flow.get")
    assert "websocket" in flow_get
    assert "payload_truncated" in flow_get
    assert "base64" in flow_get
    assert "proxy.ws.frames" in flow_get
    assert "dropped" in flow_get

    ws_frames = _tool_docstring("proxy.ws.frames")
    for field in (
        "flow_id",
        "frames",
        "offset",
        "has_more",
        "dropped",
        "invalid_state",
        "too_large",
    ):
        assert field in ws_frames
