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

import json
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


def test_recorder_rolls_close_metadata_onto_the_row() -> None:
    recorder = _FlowRecorder()
    flow = _handshake_flow("ws1")
    recorder.response(flow)
    # mitmproxy fills these on flow.websocket when the close handshake finishes.
    flow.websocket = SimpleNamespace(
        messages=[], close_code=1008, closed_by_client=False, close_reason="policy"
    )
    recorder.websocket_end(flow)

    row = next(r for r in recorder.snapshot() if r["id"] == "ws1")
    assert row["websocket"] is True
    assert row["ws_closed"] is True
    assert row["ws_close_code"] == 1008
    assert row["ws_closed_by_client"] is False
    assert row["ws_close_reason"] == "policy"


def test_recorder_accepts_the_intenum_close_code_wsproto_delivers() -> None:
    # mitmproxy stores wsproto's CloseReason IntEnum, not a plain int; a strict
    # type-is-int check dropped the code while the reason survived. Regression:
    # the enum must land as a plain JSON int.
    import enum

    class _CloseReason(enum.IntEnum):
        GOING_AWAY = 1001

    recorder = _FlowRecorder()
    flow = _handshake_flow("ws1")
    recorder.response(flow)
    flow.websocket = SimpleNamespace(
        messages=[],
        close_code=_CloseReason.GOING_AWAY,
        closed_by_client=True,
        close_reason="going away",
    )
    recorder.websocket_end(flow)

    row = next(r for r in recorder.snapshot() if r["id"] == "ws1")
    assert row["ws_close_code"] == 1001
    assert type(row["ws_close_code"]) is int


def test_recorder_close_without_a_code_still_marks_closed() -> None:
    recorder = _FlowRecorder()
    flow = _handshake_flow("ws1")
    recorder.response(flow)
    # An abnormal close (1006) can arrive with no code/reason on the object.
    flow.websocket = SimpleNamespace(
        messages=[], close_code=None, closed_by_client=True, close_reason=None
    )
    recorder.websocket_end(flow)

    row = next(r for r in recorder.snapshot() if r["id"] == "ws1")
    assert row["ws_closed"] is True
    assert row["ws_closed_by_client"] is True
    assert "ws_close_code" not in row
    assert "ws_close_reason" not in row


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


def test_flow_get_reports_how_a_closed_socket_ended(tmp_path: Path, monkeypatch: Any) -> None:
    request = SimpleNamespace(method="GET", pretty_url="ws://x/chat", headers={}, raw_content=None)
    response = SimpleNamespace(status_code=101, headers={}, raw_content=None)
    flow = SimpleNamespace(
        request=request,
        response=response,
        websocket=SimpleNamespace(
            messages=[_frame(b"bye", from_client=True)],
            close_code=1001,
            closed_by_client=True,
            close_reason="going away",
            timestamp_end=123.0,
        ),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "ws1", tmp_path)

    assert payload["websocket_closed"] is True
    assert payload["websocket_close_code"] == 1001
    assert payload["websocket_closed_by_client"] is True
    assert payload["websocket_close_reason"] == "going away"


def test_flow_get_on_a_live_socket_has_no_closed_keys(tmp_path: Path, monkeypatch: Any) -> None:
    request = SimpleNamespace(method="GET", pretty_url="ws://x/chat", headers={}, raw_content=None)
    response = SimpleNamespace(status_code=101, headers={}, raw_content=None)
    # mitmproxy keeps all three None while the connection is active.
    flow = SimpleNamespace(
        request=request,
        response=response,
        websocket=SimpleNamespace(
            messages=[_frame(b"hi", from_client=True)],
            close_code=None,
            closed_by_client=None,
            close_reason=None,
            timestamp_end=None,
        ),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "ws1", tmp_path)

    assert payload["websocket"] is True
    assert "websocket_closed" not in payload
    assert "websocket_close_code" not in payload


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


def test_export_har_carries_ws_frames_as_websocketmessages(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # A plain flow and a WebSocket in the same capture: only the socket entry
    # gets _webSocketMessages built from the frames on its raw flow, and the
    # plain one is untouched.
    ws_flow = SimpleNamespace(
        websocket=SimpleNamespace(
            messages=[
                _frame(b'{"op":"subscribe"}', from_client=True),
                _frame(b'{"tick":1}', from_client=False),
                _frame(b"\x00\x01\x02\xff", from_client=False),  # binary
            ]
        )
    )
    summaries = [
        {
            "id": "p1",
            "method": "GET",
            "url": "http://x/y",
            "status": 200,
            "content_type": "text/html",
            "response_size": 2,
        },
        {
            "id": "ws1",
            "method": "GET",
            "url": "ws://x/chat",
            "status": 101,
            "content_type": "",
            "response_size": 0,
            "websocket": True,
            "ws_messages": 3,
            "ws_bytes": 32,
        },
    ]

    class _Recorder:
        def snapshot(self) -> list[dict[str, Any]]:
            return summaries

        def raw(self, flow_id: str) -> Any:
            return ws_flow if flow_id == "ws1" else None

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    out = tmp_path / "capture.har"
    result = backend.export_har("s", out)
    assert result["entry_count"] == 2

    log = json.loads(out.read_text(encoding="utf-8"))["log"]
    by_url = {e["request"]["url"]: e for e in log["entries"]}
    assert "_webSocketMessages" not in by_url["http://x/y"]

    ws_entry = by_url["ws://x/chat"]
    assert ws_entry["response"]["status"] == 101
    assert ws_entry["_webSocketMessages"] == [
        {"type": "send", "opcode": 1, "data": '{"op":"subscribe"}'},
        {"type": "receive", "opcode": 1, "data": '{"tick":1}'},
        {"type": "receive", "opcode": 2, "data": ""},
    ]
