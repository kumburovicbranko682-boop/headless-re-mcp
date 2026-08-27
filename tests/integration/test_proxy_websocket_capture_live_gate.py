"""proxy WebSocket live gate: real frames are captured, not lost behind a 101.

The bug: the capture addon wired only `response`/`error`, so a WebSocket -- which
mitmproxy delivers as one flow (a 101 handshake, then a frame per
`websocket_message`) -- showed up in proxy.flows as a bare status-101 row and
proxy.flow.get returned no frames, even though mitmproxy held every frame on
flow.websocket.messages. The application protocol an RE session is here for was
silently dropped.

This gate drives a real WebSocket conversation through a real mitmproxy: a
`websockets` echo origin answers each message with "echo:"+msg, and a
`websockets` client connects *through* the started proxy and exchanges two
messages. It then asserts the flow's row advertises the traffic
(websocket=true, ws_messages counts both directions) and that flow.get returns
the actual frames with their text and direction. Guarding the guard: the origin
transforms each message ("echo:"+msg), so seeing both the client's "hello" and
the server's distinct "echo:hello" proves both directions round-tripped through
the proxy and were captured -- not one side echoed back by accident. skip !=
pass: it skips only when mitmproxy or the websockets client is genuinely absent.
"""

from __future__ import annotations

import asyncio
import socket
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


def _websockets_available() -> bool:
    try:
        import websockets.asyncio.client  # noqa: F401
        import websockets.asyncio.server  # noqa: F401
    except Exception:
        return False
    return True


async def _exchange(origin_port: int, proxy_port: int) -> None:
    from websockets.asyncio.client import connect
    from websockets.asyncio.server import serve

    async def echo(ws: object) -> None:
        async for message in ws:  # type: ignore[attr-defined]
            await ws.send("echo:" + message)  # type: ignore[attr-defined]

    async with serve(echo, "127.0.0.1", origin_port):
        uri = f"ws://127.0.0.1:{origin_port}/chat"
        proxy = f"http://127.0.0.1:{proxy_port}"
        async with connect(uri, proxy=proxy, open_timeout=15) as ws:
            await ws.send("hello")
            assert await asyncio.wait_for(ws.recv(), timeout=15) == "echo:hello"
            await ws.send("world")
            assert await asyncio.wait_for(ws.recv(), timeout=15) == "echo:world"


@pytest.mark.integration
def test_proxy_captures_websocket_frames_both_directions(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — WebSocket capture gate not run (skip != pass)")
    if not _websockets_available():
        pytest.skip("websockets not installed — WebSocket capture gate not run (skip != pass)")

    backend = ProxyBackend()
    proxy_port = _free_port()
    origin_port = _free_port()
    started = backend.start("ws-gate", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        asyncio.run(_exchange(origin_port, proxy_port))

        ws_row: dict | None = None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            for candidate in backend.flows("ws-gate", offset=0, limit=50)["flows"]:
                if str(candidate.get("url", "")).endswith("/chat"):
                    ws_row = candidate
                    break
            if ws_row is not None and int(ws_row.get("ws_messages") or 0) >= 4:
                break
            ws_row = None
            time.sleep(0.2)

        assert ws_row is not None, "the WebSocket flow never showed its frames"
        assert ws_row["status"] == 101
        assert ws_row["websocket"] is True
        # Two client frames + two server frames.
        assert ws_row["ws_messages"] >= 4, ws_row
        assert ws_row["ws_bytes"] > 0

        detail = backend.flow_get("ws-gate", ws_row["id"], tmp_path)
        assert detail["websocket"] is True
        texts = {(m["from_client"], m.get("text")) for m in detail["websocket_messages"]}
        # Guarding the guard: the client sent "hello"; the origin transformed it
        # to a distinct "echo:hello". Both being present proves both directions
        # crossed the real proxy and were captured, not one side reflected.
        assert (True, "hello") in texts, texts
        assert (False, "echo:hello") in texts, texts
    finally:
        backend.stop("ws-gate")
