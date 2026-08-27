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
the actual frames with their text and direction. A binary frame carrying
non-UTF-8 bytes is exchanged too, and the gate asserts it comes back
retrievable as base64 (not a dead "omitted") through both flow.get and the
HAR -- a binary WebSocket protocol is what an RE session most needs to read.
proxy.export_har carries those frames as Chrome DevTools' _webSocketMessages
array (binary data base64, opcode 2, with each frame's wall-clock time)
rather than leaving a bare 101 entry. Frames are classified text vs binary by
their real opcode, and each carries the timestamp it crossed.
The client then closes with a distinctive 1001
"going away", and the gate asserts the close lands on the row (ws_closed,
ws_close_code, ws_closed_by_client) and in flow.get -- how a socket ended is an
RE signal too. Guarding the guard: the origin transforms each message
("echo:"+msg), so seeing both the client's "hello" and the server's distinct
"echo:hello" proves both directions round-tripped through the proxy and were
captured -- not one side echoed back by accident. skip != pass: it skips only
when mitmproxy or the websockets client is genuinely absent.
"""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_BINARY_FRAME = b"\x00\x01\x02\xff\xfe\x80payload"


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
            if isinstance(message, bytes):
                await ws.send(b"echo:" + message)  # type: ignore[attr-defined]
            else:
                await ws.send("echo:" + message)  # type: ignore[attr-defined]

    async with serve(echo, "127.0.0.1", origin_port):
        uri = f"ws://127.0.0.1:{origin_port}/chat"
        proxy = f"http://127.0.0.1:{proxy_port}"
        async with connect(uri, proxy=proxy, open_timeout=15) as ws:
            await ws.send("hello")
            assert await asyncio.wait_for(ws.recv(), timeout=15) == "echo:hello"
            # A binary frame carrying non-UTF-8 bytes: what a real binary
            # protocol (protobuf, msgpack) looks like. It must come back
            # retrievable, not as a dead "omitted".
            await ws.send(_BINARY_FRAME)
            assert await asyncio.wait_for(ws.recv(), timeout=15) == b"echo:" + _BINARY_FRAME
            # Close with a distinctive code so the capture's close metadata is
            # checkable below (1001 "going away", client-initiated).
            await ws.close(code=1001, reason="going away")


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

        # The client closed with 1001 "going away"; websocket_end lands just
        # after the last frame, so give the close its own poll.
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            row = next(
                (
                    c
                    for c in backend.flows("ws-gate", offset=0, limit=50)["flows"]
                    if c.get("id") == ws_row["id"]
                ),
                None,
            )
            if row is not None and row.get("ws_closed"):
                ws_row = row
                break
            time.sleep(0.2)
        assert ws_row.get("ws_closed") is True, ws_row
        assert ws_row.get("ws_close_code") == 1001, ws_row
        assert ws_row.get("ws_closed_by_client") is True, ws_row

        detail = backend.flow_get("ws-gate", ws_row["id"], tmp_path)
        assert detail["websocket"] is True
        msgs = detail["websocket_messages"]
        texts = {(m["from_client"], m.get("text")) for m in msgs}
        # Guarding the guard: the client sent "hello"; the origin transformed it
        # to a distinct "echo:hello". Both being present proves both directions
        # crossed the real proxy and were captured, not one side reflected.
        assert (True, "hello") in texts, texts
        assert (False, "echo:hello") in texts, texts
        # The binary frame is retrievable as base64, not dropped as "omitted":
        # the client's raw bytes and the origin's echo of them both survive.
        blobs = {
            base64.b64decode(m["base64"]) for m in msgs if "base64" in m
        }
        assert _BINARY_FRAME in blobs, blobs
        assert b"echo:" + _BINARY_FRAME in blobs, blobs
        # Every captured frame carries a wall-clock timestamp, and they run
        # forward -- what an analyst reads heartbeat/latency timing from.
        times = [m["time"] for m in msgs]
        assert all(isinstance(t, float) and t > 0 for t in times), times
        assert times == sorted(times), times
        assert detail["websocket_closed"] is True
        assert detail["websocket_close_code"] == 1001
        assert detail["websocket_closed_by_client"] is True

        # The exported HAR must carry the frames, not just a 101 entry: Chrome
        # DevTools reads them from the _webSocketMessages array.
        exported = backend.export_har("ws-gate", tmp_path / "capture.har")
        har = json.loads(Path(exported["path"]).read_text(encoding="utf-8"))
        ws_entries = [
            e for e in har["log"]["entries"] if str(e["request"]["url"]).endswith("/chat")
        ]
        assert ws_entries, "the WebSocket was absent from the HAR"
        frames = ws_entries[0].get("_webSocketMessages")
        assert frames, "the HAR entry carried no _webSocketMessages"
        pairs = {(m["type"], m.get("data")) for m in frames}
        assert ("send", "hello") in pairs, pairs
        assert ("receive", "echo:hello") in pairs, pairs
        # Chrome's format stores a binary frame's payload base64 in data with
        # opcode 2, so the binary payload survives the HAR round-trip too. The
        # binary frames are classified by their real opcode, so a binary frame
        # is opcode 2 even though its echo ("echo:" + bytes) starts with ASCII.
        har_blobs = {
            base64.b64decode(m["data"]) for m in frames if m.get("opcode") == 2 and m.get("data")
        }
        assert _BINARY_FRAME in har_blobs, har_blobs
        assert b"echo:" + _BINARY_FRAME in har_blobs, har_blobs
        # Every HAR frame carries Chrome's per-frame time.
        assert all(isinstance(m.get("time"), float) for m in frames), frames
    finally:
        backend.stop("ws-gate")
