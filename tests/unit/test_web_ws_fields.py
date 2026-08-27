"""WebSocket capture over CDP: frames, direction, bounding, and paging.

The web line drives Chromium over CDP but used to ignore WebSocket traffic
entirely -- a page could open a socket and stream frames and none of it was
recorded. These tests pin the capture end to end at the backend seam: drive the
real ``Network.webSocket*`` handlers with representative CDP params and assert
ws.list / ws.frames report what was sent and received, with the same bounding
(payload caps, per-connection and per-frame rings) the rest of the capture uses.
"""

from __future__ import annotations

import ast
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_WEBSOCKETS,
    _MAX_WS_FRAMES,
    _MAX_WS_PAYLOAD,
    WebBackend,
    WebError,
    _ws_entry_to_har,
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


class _Cdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, *args: Any) -> None:
        del method, args

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _Handle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.websockets: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.websockets_dropped = 0
        self.cdp = _Cdp()


def _wired(handle: _Handle) -> dict[str, Any]:
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    return handle.cdp.handlers


def _backend_for(handle: _Handle, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    return backend


def test_ws_list_and_frames_report_a_full_exchange(monkeypatch: Any) -> None:
    handle = _Handle()
    h = _wired(handle)
    h["Network.webSocketCreated"]({"requestId": "w1", "url": "ws://x/ws"})
    h["Network.webSocketHandshakeResponseReceived"](
        {"requestId": "w1", "response": {"status": 101}}
    )
    h["Network.webSocketFrameSent"](
        {"requestId": "w1", "timestamp": 1.0, "response": {"opcode": 1, "payloadData": "hello"}}
    )
    h["Network.webSocketFrameReceived"](
        {"requestId": "w1", "timestamp": 2.0, "response": {"opcode": 1, "payloadData": "world"}}
    )
    h["Network.webSocketFrameReceived"](
        {"requestId": "w1", "timestamp": 3.0, "response": {"opcode": 2, "payloadData": "AAECaw=="}}
    )
    h["Network.webSocketClosed"]({"requestId": "w1", "timestamp": 4.0})

    backend = _backend_for(handle, monkeypatch)
    listing = backend.ws_list("s")
    assert listing["total"] == 1
    row = listing["websockets"][0]
    assert row["wsId"] == "w1"
    assert row["url"] == "ws://x/ws"
    assert row["status"] == 101
    assert row["closed"] is True
    assert row["frames_sent"] == 1
    assert row["frames_received"] == 2
    # The internal frame ring never leaks into the lean list row.
    assert "_frames" not in row

    frames = backend.ws_frames("s", "w1")
    assert frames["wsId"] == "w1"
    assert frames["url"] == "ws://x/ws"
    assert frames["total"] == 3
    seen = {(f["direction"], f["type"], f["payload"]) for f in frames["frames"]}
    assert ("sent", "text", "hello") in seen
    assert ("received", "text", "world") in seen
    binary = next(f for f in frames["frames"] if f["type"] == "binary")
    assert binary["direction"] == "received"
    assert binary["opcode"] == 2
    # A binary frame's payload stays the base64 CDP handed over, verbatim.
    assert binary["payload"] == "AAECaw=="
    assert binary["payload_len"] == len("AAECaw==")


def test_ws_frames_rejects_an_unknown_id(monkeypatch: Any) -> None:
    handle = _Handle()
    _wired(handle)
    backend = _backend_for(handle, monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.ws_frames("s", "nope")
    assert excinfo.value.code == "not_found"


def test_a_frame_for_an_unseen_socket_is_dropped_not_crashed(monkeypatch: Any) -> None:
    # A frame can arrive before (or without) the create event; it must not raise
    # or invent a connection.
    handle = _Handle()
    h = _wired(handle)
    h["Network.webSocketFrameReceived"](
        {"requestId": "ghost", "response": {"opcode": 1, "payloadData": "x"}}
    )
    backend = _backend_for(handle, monkeypatch)
    assert backend.ws_list("s")["total"] == 0


def test_oversized_frame_payload_is_capped_and_flagged(monkeypatch: Any) -> None:
    handle = _Handle()
    h = _wired(handle)
    h["Network.webSocketCreated"]({"requestId": "w1", "url": "ws://x/ws"})
    big = "z" * (_MAX_WS_PAYLOAD + 100)
    h["Network.webSocketFrameReceived"](
        {"requestId": "w1", "response": {"opcode": 1, "payloadData": big}}
    )
    backend = _backend_for(handle, monkeypatch)
    frame = backend.ws_frames("s", "w1")["frames"][0]
    assert len(frame["payload"]) == _MAX_WS_PAYLOAD
    assert frame["payload_truncated"] is True
    # payload_len keeps the true on-wire size even though the preview was cut.
    assert frame["payload_len"] == _MAX_WS_PAYLOAD + 100


def test_frame_ring_evicts_oldest_and_counts_the_drop(monkeypatch: Any) -> None:
    handle = _Handle()
    h = _wired(handle)
    h["Network.webSocketCreated"]({"requestId": "w1", "url": "ws://x/ws"})
    for i in range(_MAX_WS_FRAMES + 1):
        h["Network.webSocketFrameReceived"](
            {"requestId": "w1", "response": {"opcode": 1, "payloadData": str(i)}}
        )
    backend = _backend_for(handle, monkeypatch)
    frames = backend.ws_frames("s", "w1", limit=1000)
    assert frames["total"] == _MAX_WS_FRAMES
    assert frames["dropped"] == 1
    # The oldest frame (payload "0") was evicted; the newest ("1000") survives.
    payloads = [f["payload"] for f in frames["frames"]]
    assert payloads[0] == "1"
    assert payloads[-1] == str(_MAX_WS_FRAMES)


def test_connection_ring_evicts_oldest_and_counts_the_drop(monkeypatch: Any) -> None:
    handle = _Handle()
    h = _wired(handle)
    for i in range(_MAX_WEBSOCKETS + 1):
        h["Network.webSocketCreated"]({"requestId": f"w{i}", "url": f"ws://x/{i}"})
    backend = _backend_for(handle, monkeypatch)
    listing = backend.ws_list("s")
    assert listing["total"] == _MAX_WEBSOCKETS
    assert listing["dropped"] == 1


def test_ws_list_and_frames_paginate(monkeypatch: Any) -> None:
    handle = _Handle()
    h = _wired(handle)
    for i in range(5):
        h["Network.webSocketCreated"]({"requestId": f"w{i}", "url": f"ws://x/{i}"})
    for i in range(5):
        h["Network.webSocketFrameSent"](
            {"requestId": "w0", "response": {"opcode": 1, "payloadData": str(i)}}
        )
    backend = _backend_for(handle, monkeypatch)
    page = backend.ws_list("s", offset=2, limit=2)
    assert page["offset"] == 2
    assert page["count"] == 2
    assert page["has_more"] is True

    fpage = backend.ws_frames("s", "w0", offset=3, limit=2)
    assert fpage["offset"] == 3
    assert fpage["count"] == 2
    assert fpage["has_more"] is False


def test_ws_entry_to_har_rebases_frame_times_and_carries_messages() -> None:
    handle = _Handle()
    h = _wired(handle)
    h["Network.webSocketCreated"]({"requestId": "w1", "url": "ws://x/ws"})
    h["Network.webSocketWillSendHandshakeRequest"](
        {
            "requestId": "w1",
            "wallTime": 1_700_000_000.0,
            "timestamp": 1000.0,
            "request": {"headers": {"Upgrade": "websocket", "Cookie": "sid=abc"}},
        }
    )
    h["Network.webSocketHandshakeResponseReceived"](
        {
            "requestId": "w1",
            "response": {
                "status": 101,
                "statusText": "Switching Protocols",
                "headers": {"Set-Cookie": "t=1; Path=/"},
            },
        }
    )
    h["Network.webSocketFrameSent"](
        {"requestId": "w1", "timestamp": 1000.5, "response": {"opcode": 1, "payloadData": "hi"}}
    )
    h["Network.webSocketFrameReceived"](
        {"requestId": "w1", "timestamp": 1001.0, "response": {"opcode": 2, "payloadData": "AAE="}}
    )

    ent = _ws_entry_to_har(handle.websockets["w1"])
    assert ent["_resourceType"] == "websocket"
    assert ent["request"]["method"] == "GET"
    assert ent["request"]["url"] == "ws://x/ws"
    assert ent["response"]["status"] == 101
    assert any(c["name"] == "sid" for c in ent["request"]["cookies"])
    assert any(c["name"] == "t" for c in ent["response"]["cookies"])
    # The handshake wall time anchors the entry (not the 1970 epoch fallback).
    assert datetime.fromisoformat(ent["startedDateTime"]).year == 2023

    messages = ent["_webSocketMessages"]
    send = next(m for m in messages if m["type"] == "send")
    # Monotonic frame ts rebased onto epoch: wall + (frame_ts - handshake_ts).
    assert send["time"] == 1_700_000_000.5
    assert send["data"] == "hi"
    receive = next(m for m in messages if m["type"] == "receive")
    assert receive["opcode"] == 2
    assert receive["time"] == 1_700_000_001.0


def test_ws_list_row_hides_internal_har_meta(monkeypatch: Any) -> None:
    handle = _Handle()
    h = _wired(handle)
    h["Network.webSocketCreated"]({"requestId": "w1", "url": "ws://x/ws"})
    h["Network.webSocketWillSendHandshakeRequest"](
        {"requestId": "w1", "wallTime": 1.0, "timestamp": 2.0, "request": {"headers": {"a": "b"}}}
    )
    backend = _backend_for(handle, monkeypatch)
    row = backend.ws_list("s")["websockets"][0]
    assert "_har" not in row
    assert "_frames" not in row


def test_ws_tool_descriptions_name_the_payload_fields() -> None:
    listing = _tool_docstring("web.ws.list")
    assert "websockets" in listing
    assert "frames_sent" in listing
    assert "web.ws.frames" in listing

    frames = _tool_docstring("web.ws.frames")
    assert "direction" in frames
    assert "opcode" in frames
    assert "payload_truncated" in frames
    assert "base64" in frames
