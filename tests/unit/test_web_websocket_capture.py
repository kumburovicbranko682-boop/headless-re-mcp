"""A page's WebSocket must be listed and its frames retrievable, not invisible.

CDP delivers a page WebSocket through Network.webSocketCreated (not
requestWillBeSent) and pushes each frame via webSocketFrameSent/Received. The
capture wired neither, so web.network.list never showed the socket at all and
its frames -- the application protocol an RE session is after -- were lost.
These tests drive the real event callbacks with recorded CDP payloads (no
browser): the connection appears as a WebSocket row with frame counters, and
web.network.get returns the retained frames bounded, with control frames skipped
and a flood truncated with an honest count.
"""

from __future__ import annotations

import base64
import threading
from collections import OrderedDict, deque
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.backends.web.client import _MAX_WS_FRAMES_TOTAL, _MAX_WS_MESSAGES


class _CapturingCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Callable[[dict[str, Any]], None]] = {}

    def send(self, *args: object, **kwargs: object) -> None:
        return None

    def on(self, name: str, callback: Callable[[dict[str, Any]], None]) -> None:
        self.handlers[name] = callback


def _wired() -> tuple[WebBackend, SimpleNamespace, _CapturingCdp]:
    backend = WebBackend()
    cdp = _CapturingCdp()
    handle = SimpleNamespace(
        cdp=cdp,
        lock=threading.RLock(),
        requests=OrderedDict(),
        requests_dropped=0,
        scripts=OrderedDict(),
        scripts_dropped=0,
        console=deque(maxlen=64),
        console_dropped=0,
        ws_frames=deque(maxlen=_MAX_WS_FRAMES_TOTAL),
    )
    backend._wire_events(handle)  # type: ignore[arg-type]
    return backend, handle, cdp


def _text_frame(rid: str, text: str) -> dict[str, Any]:
    return {"requestId": rid, "response": {"opcode": 1, "mask": True, "payloadData": text}}


def test_websocket_is_listed_with_frame_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, handle, cdp = _wired()
    fire = cdp.handlers

    fire["Network.webSocketCreated"]({"requestId": "9", "url": "ws://x/live"})
    fire["Network.webSocketHandshakeResponseReceived"](
        {"requestId": "9", "response": {"status": 101}}
    )
    fire["Network.webSocketFrameSent"](
        {"requestId": "9", "response": {"opcode": 1, "mask": True, "payloadData": "hello"}}
    )
    fire["Network.webSocketFrameReceived"](
        {"requestId": "9", "response": {"opcode": 1, "mask": False, "payloadData": "echo:hello"}}
    )
    # A control frame (close) is not an application message: it must not count.
    fire["Network.webSocketFrameReceived"](
        {"requestId": "9", "response": {"opcode": 8, "mask": False, "payloadData": ""}}
    )

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    rows = {r["url"]: r for r in backend.network_list("s")["requests"]}
    row = rows["ws://x/live"]
    assert row["resourceType"] == "WebSocket"
    assert row["status"] == 101
    assert row["websocket"] is True
    assert row["ws_messages"] == 2
    assert row["ws_bytes"] == len(b"hello") + len(b"echo:hello")


def test_network_get_returns_frames_with_text_and_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    backend, handle, cdp = _wired()
    fire = cdp.handlers

    fire["Network.webSocketCreated"]({"requestId": "9", "url": "ws://x/live"})
    fire["Network.webSocketFrameSent"](_text_frame("9", '{"op":"subscribe"}'))
    fire["Network.webSocketFrameReceived"](
        {"requestId": "9", "response": {"opcode": 1, "mask": False, "payloadData": '{"tick":1}'}}
    )
    blob = base64.b64encode(b"\x00\x01\x02\xff").decode("ascii")
    fire["Network.webSocketFrameReceived"](
        {"requestId": "9", "response": {"opcode": 2, "mask": False, "payloadData": blob}}
    )

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    detail = backend.network_get("s", "9", tmp_path)
    assert detail["websocket"] is True
    assert detail["websocket_message_count"] == 3
    assert detail["websocket_truncated"] is False
    msgs = detail["websocket_messages"]
    assert msgs[0] == {"from_client": True, "size": 18, "text": '{"op":"subscribe"}'}
    assert msgs[1] == {"from_client": False, "size": 10, "text": '{"tick":1}'}
    assert msgs[2] == {"from_client": False, "size": 4, "omitted": "binary"}


def test_network_get_truncates_a_flood_and_reports_the_true_total(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    backend, handle, cdp = _wired()
    fire = cdp.handlers
    fire["Network.webSocketCreated"]({"requestId": "9", "url": "ws://x/live"})
    for i in range(_MAX_WS_MESSAGES + 25):
        fire["Network.webSocketFrameSent"](_text_frame("9", f"n{i}"))

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    detail = backend.network_get("s", "9", tmp_path)
    assert detail["websocket_message_count"] == _MAX_WS_MESSAGES + 25
    assert len(detail["websocket_messages"]) == _MAX_WS_MESSAGES
    assert detail["websocket_truncated"] is True


def test_a_plain_request_row_never_gets_websocket_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, handle, cdp = _wired()
    fire = cdp.handlers
    fire["Network.requestWillBeSent"](
        {"requestId": "1", "type": "Document", "request": {"url": "http://x/y", "method": "GET"}}
    )
    fire["Network.responseReceived"](
        {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}}
    )
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    row = {r["url"]: r for r in backend.network_list("s")["requests"]}["http://x/y"]
    assert "websocket" not in row
    assert "ws_messages" not in row


def test_har_export_carries_the_socket_frames_as_websocketmessages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import json

    backend, handle, cdp = _wired()
    fire = cdp.handlers

    # A plain request and a WebSocket in the same capture: only the socket entry
    # gets _webSocketMessages, and the plain one is untouched.
    fire["Network.requestWillBeSent"](
        {"requestId": "1", "type": "Document", "request": {"url": "http://x/y", "method": "GET"}}
    )
    fire["Network.responseReceived"](
        {"requestId": "1", "response": {"status": 200, "mimeType": "text/html"}}
    )
    fire["Network.webSocketCreated"]({"requestId": "9", "url": "ws://x/live"})
    fire["Network.webSocketHandshakeResponseReceived"](
        {"requestId": "9", "response": {"status": 101}}
    )
    fire["Network.webSocketFrameSent"](_text_frame("9", '{"op":"subscribe"}'))
    fire["Network.webSocketFrameReceived"](
        {"requestId": "9", "response": {"opcode": 1, "mask": False, "payloadData": '{"tick":1}'}}
    )
    blob = base64.b64encode(b"\x00\x01\x02\xff").decode("ascii")
    fire["Network.webSocketFrameReceived"](
        {"requestId": "9", "response": {"opcode": 2, "mask": False, "payloadData": blob}}
    )

    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    out = tmp_path / "capture.har"
    result = backend.har_export("s", out)
    assert result["entry_count"] == 2

    log = json.loads(out.read_text(encoding="utf-8"))["log"]
    by_url = {e["request"]["url"]: e for e in log["entries"]}
    assert "_webSocketMessages" not in by_url["http://x/y"]

    ws_entry = by_url["ws://x/live"]
    assert ws_entry["response"]["status"] == 101
    assert ws_entry["_webSocketMessages"] == [
        {"type": "send", "opcode": 1, "data": '{"op":"subscribe"}'},
        {"type": "receive", "opcode": 1, "data": '{"tick":1}'},
        {"type": "receive", "opcode": 2, "data": ""},
    ]
