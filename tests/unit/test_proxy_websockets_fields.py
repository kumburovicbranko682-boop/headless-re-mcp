"""proxy.websockets records the frames a WebSocket exchanges after the upgrade.

The HTTP flow ring only holds the upgrade handshake (a 101 flow); the frames the
app then sends over the socket -- the real-time API layer: auth tokens, RPC, live
push data -- reach mitmproxy's websocket_message hook, not response()/error().
These tests cover the text/binary frame shaper and its truncation, the direction
normaliser and its aliases, the recorder hook (records the newest frame with a
sequence number), the backend's filters (flow_id, host, direction, content
substring), paging and dropped eviction accounting, the service routing, and the
tool docstring / read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_WS_HEX_BYTES,
    _MAX_WS_MESSAGE_TEXT,
    ProxyBackend,
    _FlowRecorder,
    _normalize_ws_direction,
    _shape_ws_message,
    _ws_is_text,
)
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.proxy import build_proxy_tools


class _Msg:
    def __init__(
        self,
        content: bytes,
        *,
        from_client: bool,
        is_text: Any = True,
        mtype: Any = None,
        timestamp: float = 1.0,
    ) -> None:
        self.content = content
        self.from_client = from_client
        if is_text is not None:
            self.is_text = is_text
        if mtype is not None:
            self.type = mtype
        self.timestamp = timestamp


class _Req:
    def __init__(self, host: str, url: str) -> None:
        self.host = host
        self.pretty_url = url


class _Flow:
    def __init__(self, flow_id: str, host: str, url: str) -> None:
        self.id = flow_id
        self.request = _Req(host, url)
        self.websocket = SimpleNamespace(messages=[])


def _push(recorder: _FlowRecorder, flow: _Flow, msg: _Msg) -> None:
    flow.websocket.messages.append(msg)
    recorder.websocket_message(flow)


def test_ws_is_text_across_versions() -> None:
    assert _ws_is_text(_Msg(b"", from_client=True, is_text=True)) is True
    assert _ws_is_text(_Msg(b"", from_client=True, is_text=False)) is False
    # Older mitmproxy: an Opcode enum on .type, no is_text.
    text_op = SimpleNamespace(name="TEXT", value=1)
    bin_op = SimpleNamespace(name="BINARY", value=2)
    assert _ws_is_text(_Msg(b"", from_client=True, is_text=None, mtype=text_op)) is True
    assert _ws_is_text(_Msg(b"", from_client=True, is_text=None, mtype=bin_op)) is False
    # Neither legible -> binary, not a guess.
    assert _ws_is_text(_Msg(b"", from_client=True, is_text=None)) is False


def test_normalize_ws_direction_aliases() -> None:
    for term in ("outgoing", "client", "sent", "C2S"):
        assert _normalize_ws_direction(term) == "outgoing"
    for term in ("incoming", "server", "received", "s2c"):
        assert _normalize_ws_direction(term) == "incoming"
    assert _normalize_ws_direction("nonsense") == ""
    assert _normalize_ws_direction("") == ""
    assert _normalize_ws_direction(None) == ""


def test_shape_ws_message_text_and_binary() -> None:
    flow = _Flow("f1", "api.example.com", "wss://api.example.com/socket")
    text = _shape_ws_message(
        flow, _Msg(b'{"op":"auth","token":"abc"}', from_client=True, is_text=True)
    )
    assert text["direction"] == "outgoing" and text["from_client"] is True
    assert text["opcode"] == "text"
    assert text["host"] == "api.example.com"
    assert text["flow_id"] == "f1"
    assert '"token":"abc"' in text["text"]
    assert "hex" not in text

    binmsg = _shape_ws_message(
        flow, _Msg(b"\x00\x01\x02\xff", from_client=False, is_text=False)
    )
    assert binmsg["direction"] == "incoming"
    assert binmsg["opcode"] == "binary" and binmsg["binary"] is True
    assert binmsg["hex"] == "000102ff"
    assert binmsg["size"] == 4


def test_shape_ws_message_truncation_flags() -> None:
    flow = _Flow("f", "h", "u")
    long_text = "x" * (_MAX_WS_MESSAGE_TEXT + 50)
    row = _shape_ws_message(flow, _Msg(long_text.encode(), from_client=True, is_text=True))
    assert row["text_truncated"] is True
    assert len(row["text"]) == _MAX_WS_MESSAGE_TEXT

    big = bytes(_MAX_WS_HEX_BYTES + 20)
    brow = _shape_ws_message(flow, _Msg(big, from_client=True, is_text=False))
    assert brow["hex_truncated"] is True
    assert len(brow["hex"]) == _MAX_WS_HEX_BYTES * 2


def test_recorder_records_newest_frame_with_seq() -> None:
    recorder = _FlowRecorder(capacity=10)
    flow = _Flow("f1", "h", "u")
    _push(recorder, flow, _Msg(b"first", from_client=True, is_text=True))
    _push(recorder, flow, _Msg(b"second", from_client=False, is_text=True))
    snap = recorder.ws_snapshot()
    assert [m["seq"] for m in snap] == [1, 2]
    assert snap[0]["text"] == "first" and snap[0]["direction"] == "outgoing"
    assert snap[1]["text"] == "second" and snap[1]["direction"] == "incoming"


def test_recorder_ignores_flow_without_messages() -> None:
    recorder = _FlowRecorder(capacity=10)
    flow = _Flow("f", "h", "u")  # websocket present but no messages appended
    recorder.websocket_message(flow)
    recorder.websocket_message(SimpleNamespace(websocket=None))
    assert recorder.ws_snapshot() == []


def _backend_with_messages(monkeypatch: Any) -> ProxyBackend:
    recorder = _FlowRecorder(capacity=100)
    fa = _Flow("fa", "api.example.com", "wss://api.example.com/s")
    fb = _Flow("fb", "chat.example.com", "wss://chat.example.com/s")
    _push(recorder, fa, _Msg(b'{"cmd":"login"}', from_client=True, is_text=True))
    _push(recorder, fa, _Msg(b'{"ok":true,"session":"S1"}', from_client=False, is_text=True))
    _push(recorder, fb, _Msg(b"hello from client", from_client=True, is_text=True))
    _push(recorder, fb, _Msg(b"\xde\xad\xbe\xef", from_client=False, is_text=False))
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_backend_websockets_filters(monkeypatch: Any) -> None:
    backend = _backend_with_messages(monkeypatch)

    by_flow = backend.websockets("s", flow_id="fa")
    assert by_flow["total"] == 2
    assert {m["flow_id"] for m in by_flow["messages"]} == {"fa"}

    by_host = backend.websockets("s", host_filter="chat")
    assert by_host["total"] == 2
    assert {m["host"] for m in by_host["messages"]} == {"chat.example.com"}

    outgoing = backend.websockets("s", direction="client")
    assert {m["direction"] for m in outgoing["messages"]} == {"outgoing"}
    assert outgoing["total"] == 2

    # contains searches decoded text and the binary hex alike.
    by_text = backend.websockets("s", contains="session")
    assert by_text["total"] == 1 and by_text["messages"][0]["flow_id"] == "fa"
    by_hex = backend.websockets("s", contains="deadbeef")
    assert by_hex["total"] == 1 and by_hex["messages"][0]["binary"] is True


def test_backend_websockets_paging(monkeypatch: Any) -> None:
    backend = _backend_with_messages(monkeypatch)
    page = backend.websockets("s", offset=0, limit=2)
    assert page["count"] == 2 and page["total"] == 4 and page["has_more"] is True
    rest = backend.websockets("s", offset=2, limit=2)
    assert rest["count"] == 2 and rest["has_more"] is False


def test_backend_websockets_dropped_counts_eviction(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=100)
    # Ring capacity for ws is _MAX_WS_MESSAGES; force eviction with a tiny ring.
    recorder.ws = type(recorder.ws)(maxlen=3)
    flow = _Flow("f", "h", "u")
    for i in range(6):
        _push(recorder, flow, _Msg(f"m{i}".encode(), from_client=True, is_text=True))
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    out = backend.websockets("s")
    assert out["total"] == 3  # only the last 3 survive
    assert out["dropped"] == 3  # seq 6 - 3 retained


def test_service_proxy_websockets_routes(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    class _FakeBackend:
        def websockets(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"messages": [], "count": 0, "total": 0}

        def close_all(self) -> None:  # called during service teardown
            return None

    service = AnalysisService()
    try:
        monkeypatch.setattr(service, "_proxy_backend", _FakeBackend())
        result = service.proxy_websockets(
            "sess", offset=1, limit=5, flow_id="fa", host_filter="api", direction="server",
            contains="tok",
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["flow_id"] == "fa" and captured["direction"] == "server"
        assert captured["contains"] == "tok"
    finally:
        service.close_all()


def test_proxy_websockets_tool_docstring_and_read_only() -> None:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    doc = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if (
                            kw.arg == "name"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value == "proxy.websockets"
                        ):
                            doc = ast.get_docstring(node) or ""
    flat = " ".join(doc.split())
    assert "direction" in flat and "flow_id" in flat and "opcode" in flat
    assert "101" in flat  # explains the upgrade shows as an HTTP flow

    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "proxy.websockets" in _READ_ONLY_NAMES
