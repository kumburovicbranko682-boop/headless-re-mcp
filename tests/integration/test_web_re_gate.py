"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "add_module.wasm"

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


_SITE_HTML = (
    "<!doctype html><html><head><title>net-gate</title>"
    '<script src="/app.js"></script></head>'
    "<body>hello-net</body></html>"
)
_SITE_JS_MARKER = "net-gate-marker-9449"
# The fetch to /redir (302 -> /redir-target) makes the browser walk a redirect,
# which is how the HAR redirect-chain capture is exercised end to end.
# The app.js also seeds Web Storage so web.storage has a real local/session
# store to read back: a token in localStorage and a marker in sessionStorage.
_SITE_LOCAL_KEY = "sg_token"
_SITE_LOCAL_VALUE = "jwt-9449"
_SITE_SESSION_KEY = "sg_sess"
_SITE_SESSION_VALUE = "sess-9449"
_SITE_JS = (
    f"console.log('net-gate-ready'); window.__netgate = '{_SITE_JS_MARKER}';"
    f"try{{localStorage.setItem('{_SITE_LOCAL_KEY}','{_SITE_LOCAL_VALUE}');"
    f"sessionStorage.setItem('{_SITE_SESSION_KEY}','{_SITE_SESSION_VALUE}');}}catch(e){{}}"
    "fetch('/redir').then(()=>{window.__redirdone=1;}).catch(()=>{});\n"
)
_SITE_COOKIE_NAME = "netgate"
_SITE_COOKIE_VALUE = "chip-9449"
# An HttpOnly cookie the document sets alongside the readable one: page JS
# (document.cookie) can never see it, so it is what proves web.cookies reads the
# real CDP jar rather than what a script could scrape.
_SITE_HTTPONLY_NAME = "netgate_secure"
_SITE_HTTPONLY_VALUE = "sealed-9449"
_REDIR_PATH = "/redir"
_REDIR_TARGET = "/redir-target"


class _GateHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _REDIR_PATH:
            self.send_response(302)
            self.send_header("Location", _REDIR_TARGET)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == _REDIR_TARGET:
            body = b"redir-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        is_js = self.path == "/app.js"
        if is_js:
            body, ctype = _SITE_JS.encode("utf-8"), "application/javascript"
        else:
            body, ctype = _SITE_HTML.encode("utf-8"), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Set a cookie on the document so the browser sends it back on the
        # /app.js subresource -- which is what proves the HAR carries the real
        # Cookie/Set-Cookie headers from CDP's ExtraInfo events.
        if not is_js:
            self.send_header("Set-Cookie", f"{_SITE_COOKIE_NAME}={_SITE_COOKIE_VALUE}; Path=/")
            # A second, HttpOnly cookie: the browser stores it in the jar but
            # never exposes it to document.cookie, so web.cookies (CDP jar) must
            # still return it.
            self.send_header(
                "Set-Cookie",
                f"{_SITE_HTTPONLY_NAME}={_SITE_HTTPONLY_VALUE}; Path=/; HttpOnly",
            )
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _local_site() -> Iterator[str]:
    """Serve a two-resource page from localhost so CDP capture has real traffic.

    A ``data:`` URL never crosses the network stack, so it cannot prove the
    ``Network.*`` capture path. A tiny loopback server (document + a JS
    subresource that logs to the console) gives the browser genuine requests to
    record without reaching the internet.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _poll(fn: Callable[[], Any], predicate: Callable[[Any], bool], *, tries: int = 40) -> Any:
    """Re-run ``fn`` until ``predicate`` holds; CDP telemetry arrives async."""
    result = fn()
    for _ in range(tries):
        if predicate(result):
            return result
        time.sleep(0.25)
        result = fn()
    return result


# A deterministic binary body big enough that its base64 (~4/3 the size) exceeds
# the 200 KB inline cap and therefore spills to a file -- which is where the
# base64-vs-bytes bug lived.
_BLOB_BYTES = bytes((i * 7 + 3) & 0xFF for i in range(300_000))
_BLOB_PATH = "/blob.bin"
_BLOB_HTML = (
    "<!doctype html><html><head><title>blob-gate</title></head><body>blob"
    f"<script>fetch('{_BLOB_PATH}').then(r=>r.arrayBuffer()).then(()=>"
    "{window.__blobdone=1;});</script></body></html>"
)


class _BlobHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _BLOB_PATH:
            body, ctype = _BLOB_BYTES, "application/octet-stream"
        else:
            body, ctype = _BLOB_HTML.encode("utf-8"), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _binary_site() -> Iterator[str]:
    """Serve a page that fetches a binary blob, so CDP records a base64 body."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BlobHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


# A main document embedding a child iframe that itself embeds a grandchild, so
# the frame tree is three deep and web.frames has real nesting to flatten.
_FRAME_CHILD_PATH = "/frame-child"
_FRAME_GRAND_PATH = "/frame-grand"
_FRAME_MAIN_HTML = (
    "<!doctype html><html><head><title>frame-main</title></head><body>frame-main"
    f"<iframe src='{_FRAME_CHILD_PATH}'></iframe></body></html>"
)
_FRAME_CHILD_HTML = (
    "<!doctype html><html><head><title>frame-child</title></head><body>frame-child"
    f"<iframe src='{_FRAME_GRAND_PATH}'></iframe></body></html>"
)
_FRAME_GRAND_HTML = (
    "<!doctype html><html><head><title>frame-grand</title></head><body>frame-grand</body></html>"
)


class _FramesHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        page = {
            _FRAME_CHILD_PATH: _FRAME_CHILD_HTML,
            _FRAME_GRAND_PATH: _FRAME_GRAND_HTML,
        }.get(self.path, _FRAME_MAIN_HTML)
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _frames_site() -> Iterator[str]:
    """Serve a three-deep nested-iframe page so web.frames has a real tree."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FramesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


_WASM_PATH = "/add.wasm"
# The page instantiates a real WASM module so V8 registers a WebAssembly script
# the Debugger domain reports; that is the only way to exercise the live
# module-bytes extraction path in web.script.source.
_WASM_HTML = (
    "<!doctype html><html><head><title>wasm-gate</title></head><body>wasm"
    f"<script>fetch('{_WASM_PATH}').then(r=>r.arrayBuffer())"
    ".then(b=>WebAssembly.instantiate(b)).then(()=>{window.__wasmdone=1;});"
    "</script></body></html>"
)


class _WasmHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _WASM_PATH:
            body, ctype = _WASM_FIXTURE.read_bytes(), "application/wasm"
        else:
            body, ctype = _WASM_HTML.encode("utf-8"), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _wasm_site() -> Iterator[str]:
    """Serve a page that instantiates a WASM module from loopback."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WasmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


# A hand-rolled RFC 6455 endpoint so the gate proves CDP WebSocket capture
# against a real browser socket without pulling in a websocket dependency. The
# page opens ws://host/ws, sends one text frame, and the server pushes back a
# text and a binary frame -- exercising both the sent and received capture path.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_WS_PATH = "/ws"
_WS_CLIENT_TEXT = "ws-gate-client-9449"
_WS_TEXT_REPLY = "ws-gate-server-9449"
_WS_BINARY_REPLY = b"\x00\x01\x02\x03\xfd\xfe\xff"
_WS_HTML = (
    "<!doctype html><html><head><title>ws-gate</title></head><body>ws"
    "<script>"
    "window.__wsrecv=0;"
    f"var ws=new WebSocket('ws://'+location.host+'{_WS_PATH}');"
    "ws.binaryType='arraybuffer';"
    f"ws.onopen=function(){{ws.send('{_WS_CLIENT_TEXT}');}};"
    "ws.onmessage=function(e){window.__wsrecv++;};"
    "ws.onclose=function(){window.__wsclosed=1;};"
    "</script></body></html>"
)


def _ws_send(wfile: Any, opcode: int, payload: bytes) -> None:
    """Write one unmasked server->client frame (small payloads only)."""
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length < 65536:
        header += bytes([126]) + length.to_bytes(2, "big")
    else:
        header += bytes([127]) + length.to_bytes(8, "big")
    wfile.write(header + payload)
    wfile.flush()


def _ws_recv(rfile: Any) -> tuple[int | None, bytes]:
    """Read one masked client->server frame; returns (opcode, payload)."""
    first = rfile.read(1)
    if not first:
        return None, b""
    opcode = first[0] & 0x0F
    second = rfile.read(1)
    if not second:
        return None, b""
    masked = bool(second[0] & 0x80)
    length = second[0] & 0x7F
    if length == 126:
        length = int.from_bytes(rfile.read(2), "big")
    elif length == 127:
        length = int.from_bytes(rfile.read(8), "big")
    mask = rfile.read(4) if masked else b""
    data = rfile.read(length)
    if masked:
        data = bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))
    return opcode, data


class _WsGateHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def _serve_ws(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()  # noqa: S324 - RFC 6455 mandates SHA-1
        ).decode()
        self.wfile.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n"
        )
        self.wfile.flush()
        self.close_connection = True
        # Push both a text and a binary frame so CDP records a received frame of
        # each kind; the page's own send gives the sent-frame capture.
        _ws_send(self.wfile, 0x1, _WS_TEXT_REPLY.encode())
        _ws_send(self.wfile, 0x2, _WS_BINARY_REPLY)
        self.connection.settimeout(8.0)
        with contextlib.suppress(Exception):
            while True:
                opcode, data = _ws_recv(self.rfile)
                if opcode is None or opcode == 0x8:
                    break
                if opcode == 0x9:  # ping -> pong, then keep listening
                    _ws_send(self.wfile, 0xA, data)
                    continue
                if opcode == 0x1:  # the page's frame arrived; we can close now
                    break
        with contextlib.suppress(Exception):
            _ws_send(self.wfile, 0x8, b"")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _WS_PATH and self.headers.get("Upgrade", "").lower() == "websocket":
            self._serve_ws()
            return
        body = _WS_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _ws_site() -> Iterator[str]:
    """Serve a page that opens a WebSocket back to the same loopback server."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WsGateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


@pytest.mark.integration
def test_web_cdp_open_and_inspect() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            assert isinstance(scripts.data["scripts"], list)

            console = service.web_console(session_id)
            assert console.ok, console.error

            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert "gate" in dom.data["title"]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_cdp_captures_network_console_and_screenshot(tmp_path: Path) -> None:
    """Prove the CDP capture surface beyond DOM: network, bodies, console,
    script source, screenshot, HAR.

    ``test_web_cdp_open_and_inspect`` only reaches scripts/console/DOM on a
    ``data:`` URL, which never touches the network stack -- so ``network_list``,
    ``network_get``, ``script_source``, ``screenshot`` and ``har_export`` (the
    reasons the CDP line exists) had no end-to-end coverage. A loopback page
    that pulls a JS subresource and logs to the console gives the browser real
    traffic to record; every reader below is then asserted against that traffic.
    CDP telemetry is delivered asynchronously, so the request/console/script
    reads poll briefly. skip != pass when playwright or chromium is unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _local_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Network: the /app.js subresource must have been captured, 200.
                listing = _poll(
                    lambda: service.web_network_list(session_id, limit=200),
                    lambda r: r.ok
                    and any(str(x.get("url", "")).endswith("/app.js") for x in r.data["requests"]),
                )
                assert listing.ok, listing.error
                app = [
                    x
                    for x in listing.data["requests"]
                    if str(x.get("url", "")).endswith("/app.js")
                ]
                assert app, listing.data["requests"]
                assert app[0]["status"] == 200, app[0]

                # network_get returns the real response body for that request.
                body = service.web_network_get(session_id, str(app[0]["requestId"]))
                assert body.ok, body.error
                assert _SITE_JS_MARKER in body.data.get("body", ""), body.data

                # Console: the subresource logged a line while the page loaded.
                console = _poll(
                    lambda: service.web_console(session_id),
                    lambda r: r.ok
                    and any("net-gate-ready" in str(e.get("text", "")) for e in r.data["console"]),
                )
                assert console.ok, console.error
                assert any(
                    "net-gate-ready" in str(e.get("text", "")) for e in console.data["console"]
                ), console.data["console"]

                # Scripts + script_source: recover the subresource's JS text.
                scripts = _poll(
                    lambda: service.web_scripts(session_id, limit=200),
                    lambda r: r.ok
                    and any(str(s.get("url", "")).endswith("/app.js") for s in r.data["scripts"]),
                )
                assert scripts.ok, scripts.error
                app_scripts = [
                    s for s in scripts.data["scripts"] if str(s.get("url", "")).endswith("/app.js")
                ]
                assert app_scripts, scripts.data["scripts"]
                source = service.web_script_source(session_id, str(app_scripts[0]["scriptId"]))
                assert source.ok, source.error
                assert _SITE_JS_MARKER in source.data.get("source", ""), source.data

                # Screenshot: a real PNG lands in the session artifact tree.
                shot = service.web_screenshot(session_id)
                assert shot.ok, shot.error
                assert shot.data["size"] > 0, shot.data
                assert Path(shot.data["path"]).is_file(), shot.data

                # HAR: the capture exports with at least the two requests in it,
                # and the file is valid HAR 1.2 a viewer can open -- not the old
                # method/url-only stub that failed every HAR parser.
                def _export_log() -> dict[str, Any]:
                    h = service.web_har_export(session_id)
                    assert h.ok, h.error
                    assert h.data["entry_count"] >= 1, h.data
                    p = Path(h.data["path"])
                    assert p.is_file(), h.data
                    return json.loads(p.read_text(encoding="utf-8"))["log"]

                def _cookies_present(log: dict[str, Any]) -> bool:
                    # The ExtraInfo events that carry Set-Cookie/Cookie arrive
                    # async, so the export may briefly precede them; re-export
                    # until both directions show up (or the poll gives up).
                    js = next(
                        (e for e in log["entries"] if e["request"]["url"].endswith("/app.js")),
                        None,
                    )
                    doc = next(
                        (
                            e
                            for e in log["entries"]
                            if "text/html" in e["response"]["content"].get("mimeType", "")
                        ),
                        None,
                    )
                    if js is None or doc is None:
                        return False
                    jc = {c["name"] for c in js["request"]["cookies"]}
                    dc = {c["name"] for c in doc["response"]["cookies"]}
                    redirected = any(
                        e["request"]["url"].endswith(_REDIR_PATH)
                        and e["response"]["status"] == 302
                        for e in log["entries"]
                    )
                    return _SITE_COOKIE_NAME in jc and _SITE_COOKIE_NAME in dc and redirected

                log = _poll(_export_log, _cookies_present)
                assert log["version"] == "1.2", log
                assert log["creator"]["version"], "creator.version is required by HAR"
                sample = log["entries"][0]
                assert set(sample) >= {
                    "startedDateTime",
                    "time",
                    "request",
                    "response",
                    "cache",
                    "timings",
                }, sample
                # startedDateTime must be an ISO 8601 instant with a timezone.
                assert datetime.fromisoformat(sample["startedDateTime"]).tzinfo is not None
                assert set(sample["request"]) >= {
                    "method",
                    "url",
                    "httpVersion",
                    "cookies",
                    "headers",
                    "queryString",
                }, sample["request"]
                assert set(sample["response"]) >= {
                    "status",
                    "statusText",
                    "content",
                    "cookies",
                    "headers",
                }, sample["response"]

                # The enrichment must be real, not just structurally present:
                # the /app.js request the browser actually made carries request
                # and response headers and a finished transfer size.
                js_entry = next(
                    (e for e in log["entries"] if e["request"]["url"].endswith("/app.js")),
                    None,
                )
                assert js_entry is not None, [e["request"]["url"] for e in log["entries"]]
                req_header_names = {h["name"].lower() for h in js_entry["request"]["headers"]}
                assert "user-agent" in req_header_names, js_entry["request"]["headers"]
                # ExtraInfo enrichment: the on-the-wire Host header (absent from
                # requestWillBeSent) is merged in, proving the extra-info path.
                assert "host" in req_header_names, js_entry["request"]["headers"]
                assert js_entry["response"]["headers"], js_entry["response"]
                resp_header_names = {h["name"].lower() for h in js_entry["response"]["headers"]}
                assert "content-type" in resp_header_names, js_entry["response"]["headers"]
                assert js_entry["response"]["status"] == 200, js_entry["response"]
                assert isinstance(js_entry["response"]["bodySize"], int), js_entry["response"]
                assert js_entry["response"]["bodySize"] > 0, js_entry["response"]

                # Cookies flow both ways: the document response's Set-Cookie is
                # parsed into response.cookies, and the browser echoes it on the
                # /app.js request, parsed into that entry's request.cookies.
                doc_entry = next(
                    (
                        e
                        for e in log["entries"]
                        if e["response"]["status"] == 200
                        and "text/html" in e["response"]["content"].get("mimeType", "")
                    ),
                    None,
                )
                assert doc_entry is not None, [e["response"]["content"] for e in log["entries"]]
                resp_cookies = {c["name"]: c["value"] for c in doc_entry["response"]["cookies"]}
                assert resp_cookies.get(_SITE_COOKIE_NAME) == _SITE_COOKIE_VALUE, doc_entry[
                    "response"
                ]["cookies"]
                req_cookies = {c["name"]: c["value"] for c in js_entry["request"]["cookies"]}
                assert req_cookies.get(_SITE_COOKIE_NAME) == _SITE_COOKIE_VALUE, js_entry[
                    "request"
                ]["cookies"]
                # The response cookie preserves the Path attribute it was set with.
                doc_cookie = next(
                    c for c in doc_entry["response"]["cookies"] if c["name"] == _SITE_COOKIE_NAME
                )
                assert doc_cookie.get("path") == "/", doc_cookie

                # The redirect chain is captured as its own hop: the fetch to
                # /redir is a 302 whose redirectURL points at the target, kept as
                # a distinct entry rather than overwritten by the redirect target.
                redir_hop = next(
                    (
                        e
                        for e in log["entries"]
                        if e["request"]["url"].endswith(_REDIR_PATH)
                        and e["response"]["status"] == 302
                    ),
                    None,
                )
                assert redir_hop is not None, [
                    (e["request"]["url"], e["response"]["status"]) for e in log["entries"]
                ]
                assert redir_hop["response"]["redirectURL"].endswith(_REDIR_TARGET), redir_hop[
                    "response"
                ]["redirectURL"]
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_cookies_read_the_jar_including_httponly() -> None:
    """web.cookies must return the live jar, HttpOnly cookies included.

    The loopback document sets two cookies: a readable one and an HttpOnly one
    page JS can never see. web.cookies reads the CDP jar, so both must come
    back -- the HttpOnly cookie is the proof this is the real jar and not a
    document.cookie scrape. Each row must also carry the httpOnly flag so an
    agent can tell a session/auth cookie from a page-readable one. skip != pass
    when playwright or chromium is unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _local_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]
            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                jar = _poll(
                    lambda: service.web_cookies(session_id),
                    lambda r: r.ok
                    and {c["name"] for c in r.data["cookies"]}
                    >= {_SITE_COOKIE_NAME, _SITE_HTTPONLY_NAME},
                )
                assert jar.ok, jar.error
                by_name = {c["name"]: c for c in jar.data["cookies"]}
                # The readable cookie and its value.
                assert by_name[_SITE_COOKIE_NAME]["value"] == _SITE_COOKIE_VALUE
                assert by_name[_SITE_COOKIE_NAME]["httpOnly"] is False
                # The HttpOnly cookie only the CDP jar can see, correctly flagged.
                assert by_name[_SITE_HTTPONLY_NAME]["value"] == _SITE_HTTPONLY_VALUE
                assert by_name[_SITE_HTTPONLY_NAME]["httpOnly"] is True
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_frames_map_the_nested_iframe_tree() -> None:
    """web.frames must flatten the main frame plus its nested iframes.

    The loopback page embeds a child iframe that embeds a grandchild, so the
    tree is three deep -- nesting the main-frame DOM snapshot cannot show. Real
    chromium must report all three frames, the main one tagged is_main with a
    null parent, and each child pointing at its parent so the embedding chain is
    reconstructable. skip != pass when playwright or chromium is unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _frames_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]
            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # The child/grandchild frames load asynchronously, so poll until
                # all three are in the tree.
                got = _poll(
                    lambda: service.web_frames(session_id),
                    lambda r: r.ok
                    and any(f["url"].endswith(_FRAME_GRAND_PATH) for f in r.data["frames"]),
                    tries=80,
                )
                assert got.ok, got.error
                frames = got.data["frames"]
                by_url = {f["url"]: f for f in frames}
                main = next(f for f in frames if f["is_main"])
                child = next(f for f in frames if f["url"].endswith(_FRAME_CHILD_PATH))
                grand = next(f for f in frames if f["url"].endswith(_FRAME_GRAND_PATH))

                # The main frame is the root: no parent, depth 0.
                assert main["parentFrameId"] is None
                assert main["depth"] == 0
                # The chain reconstructs: grand -> child -> main.
                assert child["parentFrameId"] == main["frameId"], frames
                assert grand["parentFrameId"] == child["frameId"], frames
                assert child["depth"] == 1 and grand["depth"] == 2, frames
                # Only one frame is the main frame.
                assert sum(1 for f in frames if f["is_main"]) == 1, frames
                assert len(by_url) >= 3
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_storage_reads_local_and_session_stores() -> None:
    """web.storage must read back what the page put in local/session storage.

    The loopback page's script seeds a token in localStorage and a marker in
    sessionStorage -- state no cookie or network reader shows. web.storage reads
    the chosen store through the page context, so the local read must return the
    token and the session read the marker, each with its real value. The two
    stores are distinct, so a session key must not appear in the local read.
    skip != pass when playwright or chromium is unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _local_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]
            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                local = _poll(
                    lambda: service.web_storage(session_id, which="local"),
                    lambda r: r.ok
                    and any(e["key"] == _SITE_LOCAL_KEY for e in r.data["entries"]),
                )
                assert local.ok, local.error
                assert local.data["which"] == "local"
                lmap = {e["key"]: e["value"] for e in local.data["entries"]}
                assert lmap.get(_SITE_LOCAL_KEY) == _SITE_LOCAL_VALUE, local.data
                # The session key lives in a different store, not this one.
                assert _SITE_SESSION_KEY not in lmap, local.data

                session = _poll(
                    lambda: service.web_storage(session_id, which="session"),
                    lambda r: r.ok
                    and any(e["key"] == _SITE_SESSION_KEY for e in r.data["entries"]),
                )
                assert session.ok, session.error
                smap = {e["key"]: e["value"] for e in session.data["entries"]}
                assert smap.get(_SITE_SESSION_KEY) == _SITE_SESSION_VALUE, session.data
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_cdp_captures_websocket_frames() -> None:
    """Prove the CDP WebSocket capture against a real browser socket.

    The web line drives Chromium but ignored WebSocket traffic entirely, so a
    page that streamed over a socket left nothing to inspect. A loopback page
    opens ws://host/ws, sends one text frame, and the server pushes back a text
    and a binary frame; ws.list/ws.frames must then show the connection with the
    sent frame and both received frames, opcodes and payloads intact. CDP
    telemetry is async, so the reads poll. skip != pass when the browser is
    unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _ws_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                def _ws_conn() -> dict[str, Any] | None:
                    listing = service.web_ws_list(session_id)
                    if not listing.ok:
                        return None
                    return next(
                        (
                            c
                            for c in listing.data["websockets"]
                            if str(c.get("url", "")).endswith(_WS_PATH)
                        ),
                        None,
                    )

                conn = _poll(
                    _ws_conn,
                    lambda c: c is not None
                    and int(c.get("frames_sent", 0)) >= 1
                    and int(c.get("frames_received", 0)) >= 2,
                    # CDP frame events are delivered asynchronously; a warm
                    # browser settles in ~1s but a cold or loaded one can take
                    # far longer, so the budget is generous (measured: a cold
                    # chromium blew past a 20s poll while a warm one passed in 1s).
                    tries=240,
                )
                assert conn is not None, "no /ws connection was captured"
                assert conn["status"] == 101, conn
                assert conn["frames_sent"] >= 1, conn
                assert conn["frames_received"] >= 2, conn

                frames = service.web_ws_frames(session_id, str(conn["wsId"]), limit=1000)
                assert frames.ok, frames.error
                rows = frames.data["frames"]

                sent_text = [
                    f for f in rows if f["direction"] == "sent" and f["type"] == "text"
                ]
                assert any(f["payload"] == _WS_CLIENT_TEXT for f in sent_text), rows

                recv_text = [
                    f for f in rows if f["direction"] == "received" and f["type"] == "text"
                ]
                assert any(f["payload"] == _WS_TEXT_REPLY for f in recv_text), rows

                recv_binary = [
                    f for f in rows if f["direction"] == "received" and f["type"] == "binary"
                ]
                assert recv_binary, rows
                # A binary frame's payload is base64; decoding it yields the exact
                # bytes the server sent, not a lossy text rendering.
                assert any(
                    base64.b64decode(f["payload"]) == _WS_BINARY_REPLY for f in recv_binary
                ), recv_binary

                # The HAR export carries the socket too: a websocket entry whose
                # DevTools _webSocketMessages hold the same frames, so a captured
                # socket re-imports into DevTools rather than being lost.
                exported = service.web_har_export(session_id)
                assert exported.ok, exported.error
                log = json.loads(
                    Path(exported.data["path"]).read_text(encoding="utf-8")
                )["log"]
                ws_entries = [e for e in log["entries"] if e.get("_resourceType") == "websocket"]
                assert ws_entries, [e.get("_resourceType") for e in log["entries"]]
                messages = ws_entries[0]["_webSocketMessages"]
                assert any(
                    m["type"] == "send" and m["data"] == _WS_CLIENT_TEXT for m in messages
                ), messages
                assert any(
                    m["type"] == "receive" and m["data"] == _WS_TEXT_REPLY for m in messages
                ), messages
                assert any(
                    m["type"] == "receive"
                    and m["opcode"] == 2
                    and base64.b64decode(m["data"]) == _WS_BINARY_REPLY
                    for m in messages
                ), messages
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_network_get_spills_a_binary_body_as_real_bytes(tmp_path: Path) -> None:
    """A binary response body must reach disk as the resource, not base64 text.

    CDP returns binary bodies base64-encoded. network_get used to write that
    base64 *text* into the ``.bin`` artifact, so an agent pulling a WASM module,
    image or encrypted blob got a file 4/3 the real size that it still had to
    decode. Fetch a 300 KB binary through the page (its base64 exceeds the inline
    cap, so it spills), then assert base64_encoded is set and the spilled file is
    byte-for-byte the origin's payload -- not its base64. skip != pass without a
    browser.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _binary_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Wait for the fetch to be recorded *and* to have a response, so
                # getResponseBody has a body to return.
                listing = _poll(
                    lambda: service.web_network_list(session_id, limit=200),
                    lambda r: r.ok
                    and any(
                        str(x.get("url", "")).endswith(_BLOB_PATH) and x.get("status") == 200
                        for x in r.data["requests"]
                    ),
                )
                assert listing.ok, listing.error
                blob = [
                    x
                    for x in listing.data["requests"]
                    if str(x.get("url", "")).endswith(_BLOB_PATH)
                ]
                assert blob, listing.data["requests"]

                got = service.web_network_get(session_id, str(blob[0]["requestId"]))
                assert got.ok, got.error
                assert got.data.get("base64_encoded") is True, got.data
                spill = got.data.get("body_path")
                assert spill, f"large binary body must spill to disk: {got.data}"
                on_disk = Path(spill).read_bytes()
                # The artifact is the real resource, byte-for-byte -- not base64.
                assert on_disk == _BLOB_BYTES, (len(on_disk), len(_BLOB_BYTES))
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_script_source_extracts_a_live_wasm_module_for_static_analysis(
    tmp_path: Path,
) -> None:
    """A WASM module seen in a page must come out as a real .wasm the tools accept.

    CDP hands a WebAssembly script back as WAT text plus base64 module bytes;
    only the text used to be kept, so a module could be listed via web.wasm.list
    yet never fed to wasm.wat / wasm.info / ghidra, which all take a .wasm path.
    This instantiates a real module in the page, extracts it through
    web.script.source, and proves the spilled bytes are a genuine module by
    round-tripping them through wasm.wat. skip != pass without a browser.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    if not _WASM_FIXTURE.is_file():
        pytest.skip(f"wasm fixture missing: {_WASM_FIXTURE} — skip != pass")
    with _wasm_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # V8 registers the WebAssembly script asynchronously once the
                # module instantiates; poll web.wasm.list until it shows up. A
                # cold browser can take longer than the default window to fetch,
                # compile and instantiate, so allow extra tries here.
                listing = _poll(
                    lambda: service.web_wasm_list(session_id, limit=200),
                    lambda r: r.ok and bool(r.data["scripts"]),
                    tries=80,
                )
                assert listing.ok, listing.error
                wasm_scripts = listing.data["scripts"]
                assert wasm_scripts, "no WebAssembly script was reported by the page"

                source = service.web_script_source(
                    session_id, str(wasm_scripts[0]["scriptId"])
                )
                assert source.ok, source.error
                data = source.data
                assert data.get("language") == "WebAssembly", data
                module_path = data.get("wasm_bytecode_path")
                assert module_path, f"no module bytes extracted: {data}"
                assert data.get("wasm_bytes", 0) > 0, data
                assert data.get("wasm_bytecode_id"), data

                on_disk = Path(module_path).read_bytes()
                # The artifact is a genuine module: the WASM magic, real bytes.
                assert on_disk[:4] == b"\x00asm", on_disk[:8]

                # The registered id resolves to those same bytes.
                read = service.artifacts_read(
                    str(data["wasm_bytecode_id"]), offset=0, limit=4
                )
                assert read.ok and read.data is not None, read.error
                assert read.data["data"].startswith("0061736d"), read.data

                # The whole point: the extracted module round-trips through the
                # static WASM tooling. Only assert the handoff when wabt is present.
                if WasmClient().available:
                    wat = service.wasm_wat(module_path)
                    assert wat.ok, wat.error
                    assert "module" in (wat.data.get("wat") or ""), wat.data
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert isinstance(result.data["code"], str)
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_spills_full_output_when_truncated(tmp_path: Path) -> None:
    """A large real deobfuscation must remain fully recoverable, not half lost.

    Measured against live webcrack: a ~600 KB minified bundle unminifies past
    900 KB, but the inline reply caps at 400 KB, so most of the code used to be
    unrecoverable. The service now spills the full text to an artifact; this
    proves artifact_path holds every byte and the inline code is just a preview.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    big = tmp_path / "big.min.js"
    big.write_text(
        ";".join(
            f"function f{i}(a,b){{if(a>b){{return a*{i}+b}}else{{return b-a+{i}}}}}"
            for i in range(9000)
        ),
        encoding="utf-8",
    )
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(big))
        assert result.ok, result.error
        data = result.data
        assert data["truncated"] is True, "expected the bundle to overflow inline"
        assert len(data["code"].encode("utf-8")) <= 400_000
        artifact = Path(data["artifact_path"])
        assert artifact.is_file()
        full = artifact.read_bytes()
        assert len(full) == data["artifact_bytes"] == data["bytes"]
        # The artifact is the whole output; the inline code is only its prefix.
        assert len(full) > len(data["code"].encode("utf-8"))
        assert full.decode("utf-8", "ignore").startswith(data["code"][:200])
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_faults_soft_on_unparseable_input(tmp_path: Path) -> None:
    """Broken JS must fault with a structured error, not a false success.

    webcrack reports a parse failure by exiting non-zero and writing the
    SyntaxError to stderr (stdout empty) -- the mirror image of wasm-objdump,
    which put its error on stdout and slipped past the same guard. This pins the
    JS reader's half of that contract: unparseable input comes back
    backend_error (never internal_error, never ok with garbage as "code"), while
    an empty file -- which webcrack accepts -- still succeeds with empty output.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        broken = tmp_path / "broken.js"
        broken.write_text("function ( { syntax ]]] error !!!", encoding="utf-8")
        result = service.js_deobfuscate(str(broken))
        assert not result.ok and result.error is not None
        assert result.error.code == "backend_error", result.error

        binary = tmp_path / "binary.js"
        binary.write_bytes(bytes(range(64)))
        binary_result = service.js_deobfuscate(str(binary))
        assert not binary_result.ok and binary_result.error is not None
        assert binary_result.error.code == "backend_error", binary_result.error

        # An empty module is legal input, not a failure: webcrack exits 0 and the
        # reader must stay on the success path rather than over-rejecting.
        empty = tmp_path / "empty.js"
        empty.write_text("", encoding="utf-8")
        empty_result = service.js_deobfuscate(str(empty))
        assert empty_result.ok, empty_result.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        # webcrack owns the output directory: the service pre-creates a unique
        # tree for retention, so unpack has to pass --force or webcrack aborts
        # with "output directory already exists". A green here proves the whole
        # write path, not just deobfuscation to stdout.
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        assert result.data["files"], "webcrack produced no files"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_WASM_FIXTURE))
        assert result.ok, result.error
        wat = result.data["wat"]
        # A real module round-trips to a function definition and its named export,
        # not just the bare "(module" wrapper an empty module would yield.
        assert "(func" in wat
        assert '(export "add"' in wat
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_info(str(_WASM_FIXTURE))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x enumerates the section headers and details; the
        # export table names the "add" function the module deliberately exposes.
        assert "Export" in objdump
        assert "add" in objdump
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_decompile_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-decompile) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_decompile(str(_WASM_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        # wasm-decompile recovers a named function with typed params and a
        # structured body -- the C-like form, not wat's stack ops. So the export
        # name and a real return statement must be present, and the raw stack
        # opcode wasm.wat would emit (local.get) must not: that contrast is the
        # whole reason wasm.decompile exists beside wasm.wat.
        assert "function add" in code
        assert "return" in code
        assert "local.get" not in code
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_decompile_faults_soft_on_a_malformed_module(tmp_path: Path) -> None:
    """A bad .wasm through wasm-decompile must fault structured, not smuggle text.

    wasm-decompile empties stdout and writes its diagnostic to stderr on a bad
    module, so the reader must come back backend_error with the diagnostic
    reachable -- never a false success dressing "invalid section" up as a
    one-line decompilation.
    """
    if not WasmClient().available:
        pytest.skip("wabt not installed — WASM Gate not run (skip != pass)")
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b"NOPE\x01\x00\x00\x00garbage-past-the-magic")
    service = AnalysisService()
    try:
        result = service.wasm_decompile(str(bad))
        assert not result.ok and result.error is not None
        assert result.error.code == "backend_error", result.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_accepts_minimal_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # Boundary case: the smallest valid module is magic + version, no sections.
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        assert "module" in result.data["wat"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_readers_fault_soft_on_a_malformed_module(tmp_path: Path) -> None:
    """A bad .wasm must fault with a structured error, not smuggle it as output.

    wasm2wat writes its error to stderr and empties stdout, but wasm-objdump
    writes the diagnostic to STDOUT and exits non-zero -- so wasm_info used to
    return ok with "error: bad magic value" as the objdump payload, dressing a
    failed inspection up as analysis. Both readers must now come back
    backend_error (never internal_error, never a false success), and the actual
    diagnostic must be reachable so an agent learns why the module was rejected.
    """
    if not WasmClient().available:
        pytest.skip("wabt not installed — WASM Gate not run (skip != pass)")
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b"NOPE\x01\x00\x00\x00garbage-past-the-magic")
    service = AnalysisService()
    try:
        info = service.wasm_info(str(bad))
        assert not info.ok and info.error is not None
        assert info.error.code == "backend_error", info.error
        assert "magic" in str(info.error.details.get("stderr", "")).lower()

        wat = service.wasm_wat(str(bad))
        assert not wat.ok and wat.error is not None
        assert wat.error.code == "backend_error", wat.error

        # And a valid module through the same reader still succeeds, so the fix
        # rejects only genuine failures rather than every non-zero-looking run.
        good = tmp_path / "min.wasm"
        good.write_bytes(b"\x00asm\x01\x00\x00\x00")
        ok = service.wasm_info(str(good))
        assert ok.ok and ok.data is not None, ok.error
        assert "wasm" in ok.data["objdump"].lower()
    finally:
        service.close_all()
