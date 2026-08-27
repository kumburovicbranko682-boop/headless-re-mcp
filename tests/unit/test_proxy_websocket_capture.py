"""A WebSocket flow's frames must be visible, not lost behind a bare 101.

mitmproxy delivers a WebSocket as one flow: the `response` hook records its 101
handshake, then a frame arrives per `websocket_message`. The recorder only wired
`response`/`error`, so proxy.flows showed a status-101 row with response_size 0
and proxy.flow.get returned no frames -- the entire application protocol an RE
session is after was silently dropped, even though mitmproxy held every frame on
flow.websocket.messages. These tests drive the real recorder hook and flow.get
with fake mitmproxy flows (no network) and assert the row advertises the traffic
(websocket/ws_messages/ws_bytes) and flow.get returns the frames bounded.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_WS_MESSAGES,
    ProxyBackend,
    _FlowRecorder,
)


def _handshake_flow(flow_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=flow_id,
        request=SimpleNamespace(
            method="GET", pretty_url="ws://x/chat", host="x", headers={}, raw_content=None
        ),
        response=SimpleNamespace(
            status_code=101, headers={"upgrade": "websocket"}, raw_content=None
        ),
        websocket=None,
    )


def _frame(content: bytes, *, from_client: bool) -> SimpleNamespace:
    return SimpleNamespace(from_client=from_client, content=content)


def test_recorder_rolls_frame_count_and_bytes_onto_the_101_row() -> None:
    recorder = _FlowRecorder()
    flow = _handshake_flow("ws1")
    recorder.response(flow)  # records the 101 handshake summary

    # Frames arrive after the handshake; mitmproxy appends then calls the hook.
    frames: list[SimpleNamespace] = []
    flow.websocket = SimpleNamespace(messages=frames)
    for content, from_client in ((b"hello", True), (b"echo:hello", False), (b"bye", True)):
        frames.append(_frame(content, from_client=from_client))
        recorder.websocket_message(flow)

    row = next(r for r in recorder.snapshot() if r["id"] == "ws1")
    assert row["status"] == 101
    assert row["websocket"] is True
    assert row["ws_messages"] == 3
    assert row["ws_bytes"] == len(b"hello") + len(b"echo:hello") + len(b"bye")


def test_a_plain_flow_never_gets_websocket_fields() -> None:
    recorder = _FlowRecorder()
    plain = SimpleNamespace(
        id="p1",
        request=SimpleNamespace(
            method="GET", pretty_url="http://x/y", host="x", headers={}, raw_content=None
        ),
        response=SimpleNamespace(status_code=200, headers={}, raw_content=b"ok"),
    )
    recorder.response(plain)
    row = next(r for r in recorder.snapshot() if r["id"] == "p1")
    assert "websocket" not in row
    assert "ws_messages" not in row


def _backend_with_flow(monkeypatch: Any, flow: Any) -> ProxyBackend:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def test_flow_get_returns_bounded_frames_with_text_and_omitted_flags(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = SimpleNamespace(method="GET", pretty_url="ws://x/chat", headers={}, raw_content=None)
    response = SimpleNamespace(status_code=101, headers={"upgrade": "websocket"}, raw_content=None)
    frames = [
        _frame(b'{"op":"subscribe"}', from_client=True),
        _frame(b'{"tick":1}', from_client=False),
        _frame(b"\x00\x01\x02\xff\xfe", from_client=False),  # binary
        _frame(b"z" * 20000, from_client=False),  # over the per-frame inline cap
    ]
    flow = SimpleNamespace(
        request=request, response=response, websocket=SimpleNamespace(messages=frames)
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "ws1", tmp_path)

    assert payload["websocket"] is True
    assert payload["websocket_message_count"] == 4
    assert "websocket_truncated" not in payload
    msgs = payload["websocket_messages"]
    assert msgs[0] == {"from_client": True, "size": 18, "text": '{"op":"subscribe"}'}
    assert msgs[1] == {"from_client": False, "size": 10, "text": '{"tick":1}'}
    assert msgs[2]["omitted"] == "binary" and "text" not in msgs[2]
    assert msgs[3]["omitted"] == "too_large" and msgs[3]["size"] == 20000


def test_flow_get_truncates_a_flood_of_frames_and_says_so(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = SimpleNamespace(method="GET", pretty_url="ws://x/chat", headers={}, raw_content=None)
    response = SimpleNamespace(status_code=101, headers={}, raw_content=None)
    frames = [_frame(b"n", from_client=True) for _ in range(_MAX_WS_MESSAGES + 5)]
    flow = SimpleNamespace(
        request=request, response=response, websocket=SimpleNamespace(messages=frames)
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "ws1", tmp_path)

    assert payload["websocket_message_count"] == _MAX_WS_MESSAGES + 5
    assert len(payload["websocket_messages"]) == _MAX_WS_MESSAGES
    assert payload["websocket_truncated"] is True


def test_flow_get_on_a_plain_flow_has_no_websocket_keys(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = SimpleNamespace(method="GET", pretty_url="http://x/y", headers={}, raw_content=None)
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"ok")
    flow = SimpleNamespace(request=request, response=response)
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "p1", tmp_path)

    assert "websocket" not in payload
    assert "websocket_messages" not in payload
    assert "websocket_message_count" not in payload
