"""web.websockets exposes CDP-captured WebSocket connections and their frames.

Covers the capture path (driven through the _wire_events seam with a fake CDP
that records handlers, then emitting Network.webSocket* events) and the
websockets() query method (driven through the _get seam).
"""

from __future__ import annotations

import ast
from collections import OrderedDict, deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_WS_FRAMES,
    WebBackend,
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

    def send(self, method: str) -> None:
        del method

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _Handle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.headers: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.post_data: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.console: deque[dict[str, Any]] = deque()
        self.websockets: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.websockets_dropped = 0
        self.requests_dropped = 0
        self.scripts_dropped = 0
        self.console_dropped = 0
        self.cdp = _Cdp()


def _wired(handle: _Handle) -> WebBackend:
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    return backend


def _emit(handle: _Handle, event: str, params: dict[str, Any]) -> None:
    handle.cdp.handlers[event](params)


def test_captures_a_socket_lifecycle_and_frames() -> None:
    handle = _Handle()
    backend = _wired(handle)
    _emit(handle, "Network.webSocketCreated", {"requestId": "w1", "url": "wss://c2.example/rt"})
    _emit(
        handle,
        "Network.webSocketFrameSent",
        {"requestId": "w1", "response": {"opcode": 1, "payloadData": "auth:token"}},
    )
    _emit(
        handle,
        "Network.webSocketFrameReceived",
        {"requestId": "w1", "response": {"opcode": 1, "payloadData": "ok"}},
    )
    _emit(handle, "Network.webSocketClosed", {"requestId": "w1"})

    payload = backend.websockets("s")
    assert payload["count"] == 1
    conn = payload["websockets"][0]
    assert conn["url"] == "wss://c2.example/rt"
    assert conn["closed"] is True
    assert conn["frames_sent"] == 1
    assert conn["frames_received"] == 1
    assert conn["bytes_sent"] == len("auth:token")
    directions = [f["direction"] for f in conn["frames"]]
    assert directions == ["sent", "received"]
    assert conn["frames"][0]["data"] == "auth:token"
    assert conn["frames"][0]["opcode"] == 1


def test_frame_before_created_still_makes_a_connection() -> None:
    handle = _Handle()
    backend = _wired(handle)
    _emit(
        handle,
        "Network.webSocketFrameReceived",
        {"requestId": "late", "response": {"opcode": 1, "payloadData": "hi"}},
    )
    conn = backend.websockets("s")["websockets"][0]
    assert conn["requestId"] == "late"
    assert conn["frames_received"] == 1
    assert conn["url"] == ""


def test_error_is_recorded() -> None:
    handle = _Handle()
    backend = _wired(handle)
    _emit(handle, "Network.webSocketCreated", {"requestId": "w2", "url": "wss://x/y"})
    _emit(
        handle,
        "Network.webSocketFrameError",
        {"requestId": "w2", "errorMessage": "handshake failed"},
    )
    conn = backend.websockets("s")["websockets"][0]
    assert conn["error"] == "handshake failed"


def test_large_frame_payload_is_bounded() -> None:
    handle = _Handle()
    backend = _wired(handle)
    _emit(handle, "Network.webSocketCreated", {"requestId": "w3", "url": "wss://x"})
    _emit(
        handle,
        "Network.webSocketFrameReceived",
        {"requestId": "w3", "response": {"opcode": 1, "payloadData": "A" * 100_000}},
    )
    frame = backend.websockets("s")["websockets"][0]["frames"][0]
    assert frame["truncated"] is True
    assert len(frame["data"]) < 100_000
    assert frame["size"] == 100_000  # original length is preserved


def test_frame_ring_is_bounded_and_counts_drops() -> None:
    handle = _Handle()
    backend = _wired(handle)
    _emit(handle, "Network.webSocketCreated", {"requestId": "w4", "url": "wss://x"})
    for i in range(_MAX_WS_FRAMES + 25):
        _emit(
            handle,
            "Network.webSocketFrameReceived",
            {"requestId": "w4", "response": {"opcode": 1, "payloadData": f"m{i}"}},
        )
    conn = backend.websockets("s", frames_limit=_MAX_WS_FRAMES)["websockets"][0]
    assert conn["frames_received"] == _MAX_WS_FRAMES + 25
    assert conn["frames_retained"] == _MAX_WS_FRAMES
    assert conn["frames_dropped"] == 25
    # Newest tail is retained: the last frame emitted is present.
    assert conn["frames"][-1]["data"] == f"m{_MAX_WS_FRAMES + 24}"


def test_frames_limit_returns_newest_tail() -> None:
    handle = _Handle()
    backend = _wired(handle)
    _emit(handle, "Network.webSocketCreated", {"requestId": "w5", "url": "wss://x"})
    for i in range(10):
        _emit(
            handle,
            "Network.webSocketFrameSent",
            {"requestId": "w5", "response": {"opcode": 1, "payloadData": str(i)}},
        )
    conn = backend.websockets("s", frames_limit=3)["websockets"][0]
    assert conn["frames_returned"] == 3
    assert conn["frames_retained"] == 10
    assert [f["data"] for f in conn["frames"]] == ["7", "8", "9"]


def test_no_sockets_is_empty() -> None:
    handle = _Handle()
    backend = _wired(handle)
    payload = backend.websockets("s")
    assert payload["websockets"] == []
    assert payload["count"] == 0
    assert payload["total"] == 0
    assert payload["connections_dropped"] == 0


def test_service_web_websockets_dispatch() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    _emit(handle, "Network.webSocketCreated", {"requestId": "w6", "url": "wss://svc/x"})

    service = AnalysisService(Settings.load())
    service._web_backend._get = lambda _sid: handle  # type: ignore[attr-defined]
    result = service.web_websockets("s")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["websockets"][0]["url"] == "wss://svc/x"


def test_web_websockets_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_web_tools(service)}
    assert "web.websockets" in names


def test_web_websockets_docstring_names_the_shape() -> None:
    doc = " ".join(_tool_docstring("web.websockets").split())
    assert "frames_sent" in doc
    assert "frames_received" in doc
    assert "opcode" in doc
    assert "connections_dropped" in doc
    assert "direction" in doc
