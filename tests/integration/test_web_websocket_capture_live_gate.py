"""web WebSocket live gate: a page's socket is listed and its frames captured.

The bug: CDP delivers a page WebSocket through Network.webSocketCreated (not
requestWillBeSent) and pushes each frame via webSocketFrameSent/Received. The
capture wired neither, so web.network.list never showed the socket and its
frames were lost -- yet the frames are exactly the application protocol an RE
session opened the browser to read.

This gate drives a real Chromium at a real page that opens a WebSocket to a
`websockets` echo origin (which answers "echo:"+msg) and exchanges two messages.
It asserts the socket now appears in web.network.list as a WebSocket row with
frame counters, and that web.network.get returns the frames both directions.
The page then closes the socket, and the gate asserts the row picks up
ws_closed=true -- a socket the server kicked must not read as still streaming.
Guarding the guard: the origin transforms each message, so seeing the client's
"hello" and the origin's distinct "echo:hello" proves both directions were
captured, not one side reflected. skip != pass: it skips only when Chromium or
the websockets server is genuinely unavailable.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


def _websockets_available() -> bool:
    try:
        import websockets.sync.server  # noqa: F401
    except Exception:
        return False
    return True


def _wait_ws_ready(port: int) -> None:
    """Block until the echo server actually answers a WebSocket handshake.

    serve() binds and listens synchronously, but the accept loop only runs once
    serve_forever is scheduled -- and under a cold Chromium launch that thread
    can be starved long enough that the browser's connect completes the TCP but
    hangs in CONNECTING waiting for an upgrade that never comes, producing no
    onopen/onclose/onerror to retry from. Driving one real client handshake here
    forces the accept loop live before we navigate, so the browser's connect is
    answered immediately.
    """
    from websockets.sync.client import connect

    deadline = time.monotonic() + 8.0
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with connect(f"ws://127.0.0.1:{port}/probe", open_timeout=2) as client:
                client.send("ping")
                assert client.recv() == "echo:ping"
            return
        except Exception as exc:  # noqa: BLE001 - retry until the loop is live
            last = exc
            time.sleep(0.1)
    raise RuntimeError(f"echo server never answered a handshake: {last}")


@contextmanager
def _ws_echo(port: int) -> Iterator[None]:
    from websockets.sync.server import serve

    def echo(ws: object) -> None:
        for message in ws:  # type: ignore[attr-defined]
            ws.send("echo:" + message)  # type: ignore[attr-defined]

    server = serve(echo, "127.0.0.1", port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _wait_ws_ready(port)
        yield
    finally:
        server.shutdown()


@contextmanager
def _page(ws_port: int) -> Iterator[str]:
    # One round trip is all the gate needs: the client "hello" and the origin's
    # distinct "echo:hello" already prove both directions were captured. The
    # origin's accept loop is confirmed live before we navigate (_wait_ws_ready),
    # so a plain connect is reliable; a second round trip only added a frame that
    # could lag past the poll deadline and read as a failure.
    body = (
        "<html><head><title>ws-gate</title><script>\n"
        f'var ws = new WebSocket("ws://127.0.0.1:{ws_port}/live");\n'
        'ws.onopen = function () { ws.send("hello"); };\n'
        # Close only after the round trip landed, so the frame capture is done
        # before the close event the gate also asserts on.
        "ws.onmessage = function (e) { window.__got = e.data; ws.close(); };\n"
        "</script></head><body>ws gate</body></html>"
    ).encode()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.integration
def test_web_lists_a_websocket_and_returns_its_frames() -> None:
    if not _browser_available():
        pytest.skip("playwright/chromium not installed — web WebSocket gate not run (skip != pass)")
    if not _websockets_available():
        pytest.skip("websockets not installed — web WebSocket gate not run (skip != pass)")

    ws_port = _free_port()
    service = AnalysisService()
    try:
        with _ws_echo(ws_port), _page(ws_port) as page_url:
            created = service.create_session(page_url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Poll until both directions have actually been captured, checked
                # against the frames network.get returns -- exactly what the gate
                # asserts -- rather than a raw count that could race the last
                # frame's arrival.
                ws_row: dict | None = None
                data: dict | None = None
                deadline = time.monotonic() + 40.0
                while time.monotonic() < deadline:
                    listed = service.web_network_list(session_id, limit=200)
                    assert listed.ok, listed.error
                    row = next(
                        (
                            r
                            for r in listed.data["requests"]
                            if str(r.get("url", "")).endswith("/live")
                        ),
                        None,
                    )
                    if row is not None and int(row.get("ws_messages") or 0) >= 2:
                        detail = service.web_network_get(session_id, str(row["requestId"]))
                        if detail.ok:
                            texts = {
                                (m["from_client"], m.get("text"))
                                for m in detail.data.get("websocket_messages", [])
                            }
                            if (True, "hello") in texts and (False, "echo:hello") in texts:
                                ws_row = row
                                data = detail.data
                                break
                    time.sleep(0.25)

                assert ws_row is not None, "the WebSocket's two-way frames never appeared"
                assert ws_row["resourceType"] == "WebSocket"
                assert ws_row["status"] == 101
                assert ws_row["websocket"] is True
                assert ws_row["ws_messages"] >= 2, ws_row
                assert ws_row["ws_bytes"] > 0

                assert data is not None
                assert data["websocket"] is True
                texts = {(m["from_client"], m.get("text")) for m in data["websocket_messages"]}
                assert (True, "hello") in texts, texts
                assert (False, "echo:hello") in texts, texts

                # The page closed the socket right after the echo; the closed
                # flag lands via Network.webSocketClosed a beat later, so poll
                # for it separately. A closed socket must not read as live.
                deadline = time.monotonic() + 20.0
                closed_row: dict | None = None
                while time.monotonic() < deadline:
                    listed = service.web_network_list(session_id, limit=200)
                    assert listed.ok, listed.error
                    row = next(
                        (
                            r
                            for r in listed.data["requests"]
                            if str(r.get("url", "")).endswith("/live")
                        ),
                        None,
                    )
                    if row is not None and row.get("ws_closed"):
                        closed_row = row
                        break
                    time.sleep(0.25)
                assert closed_row is not None, "the socket's close was never captured"
                assert closed_row["ws_closed"] is True

                # The exported HAR must carry the frames, not just a 101 entry:
                # Chrome DevTools reads them from the _webSocketMessages array.
                exported = service.web_har_export(session_id)
                assert exported.ok, exported.error
                har = json.loads(Path(exported.data["path"]).read_text(encoding="utf-8"))
                ws_entries = [
                    e
                    for e in har["log"]["entries"]
                    if str(e["request"]["url"]).endswith("/live")
                ]
                assert ws_entries, "the WebSocket was absent from the HAR"
                frames = ws_entries[0].get("_webSocketMessages")
                assert frames, "the HAR entry carried no _webSocketMessages"
                pairs = {(m["type"], m.get("data")) for m in frames}
                assert ("send", "hello") in pairs, pairs
                assert ("receive", "echo:hello") in pairs, pairs
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
