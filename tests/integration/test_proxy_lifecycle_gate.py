"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import socket
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _port_accepts

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "add_module.wasm"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


_ORIGIN_MARKER = "proxy-origin-marker-9449"
_ORIGIN_COOKIE_NAME = "proxysess"
_ORIGIN_COOKIE_VALUE = "cookie-9449"


class _OriginHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = f"{_ORIGIN_MARKER}:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Set-Cookie", f"{_ORIGIN_COOKIE_NAME}={_ORIGIN_COOKIE_VALUE}; Path=/; HttpOnly"
        )
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length) if length else b""
        body = _ORIGIN_MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _origin_site() -> Iterator[str]:
    """A loopback HTTP origin for the proxy to forward to and record."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


class _CountingOriginServer(ThreadingHTTPServer):
    """Loopback origin that counts the GETs it actually served.

    Replay is only proven if the origin sees the request a *second* time, so the
    server -- not the client -- has to be the witness.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hits = 0
        self.hits_lock = threading.Lock()


class _CountingHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        server = self.server
        assert isinstance(server, _CountingOriginServer)
        with server.hits_lock:
            server.hits += 1
        body = _ORIGIN_MARKER.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _counting_origin() -> Iterator[_CountingOriginServer]:
    server = _CountingOriginServer(("127.0.0.1", 0), _CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _poll(fn: Callable[[], Any], predicate: Callable[[Any], bool], *, tries: int = 40) -> Any:
    result = fn()
    for _ in range(tries):
        if predicate(result):
            return result
        time.sleep(0.25)
        result = fn()
    return result


@pytest.mark.integration
def test_proxy_records_traffic_forwarded_through_it(tmp_path: Path) -> None:
    """A request routed through the proxy must show up as a readable flow.

    The lifecycle gates prove the port opens and closes; none proves the proxy
    actually *captures* anything, which is the entire point of the line. Stand up
    a loopback origin, route a real HTTP GET through the running proxy to it, and
    assert the flow was recorded (method, url, 200), that flow_get returns the
    origin's response body, and that HAR export contains the entry. Plain HTTP so
    no CA trust is needed; mitmproxy records asynchronously, so the read polls.
    skip != pass when mitmproxy is unavailable.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("capture", host="127.0.0.1", port=proxy_port)
    try:
        with _origin_site() as origin:
            target = f"{origin}/hello"
            handler = urllib.request.ProxyHandler(
                {"http": f"http://127.0.0.1:{proxy_port}"}
            )
            opener = urllib.request.build_opener(handler)
            with opener.open(target, timeout=15.0) as response:
                fetched = response.read().decode("utf-8", errors="replace")
            # Sanity: the client really reached the origin through the proxy.
            assert _ORIGIN_MARKER in fetched, fetched

            listing = _poll(
                lambda: backend.flows("capture", limit=100),
                lambda r: any(str(f.get("url", "")).endswith("/hello") for f in r["flows"]),
            )
            hits = [f for f in listing["flows"] if str(f.get("url", "")).endswith("/hello")]
            assert hits, listing["flows"]
            flow = hits[0]
            assert flow["method"] == "GET", flow
            assert flow["status"] == 200, flow

            detail = backend.flow_get("capture", str(flow["id"]), tmp_path)
            assert detail["response"]["status"] == 200, detail
            body = detail["response"].get("body", "")
            assert _ORIGIN_MARKER in body, detail

            har_path = tmp_path / "capture.har"
            har = backend.export_har("capture", har_path)
            assert har["entry_count"] >= 1, har
            assert har_path.is_file()
    finally:
        backend.close_all()


_REQUIRED_ENTRY = {"startedDateTime", "time", "request", "response", "cache", "timings"}
_REQUIRED_REQUEST = {
    "method",
    "url",
    "httpVersion",
    "cookies",
    "headers",
    "queryString",
    "headersSize",
    "bodySize",
}
_REQUIRED_RESPONSE = {
    "status",
    "statusText",
    "httpVersion",
    "cookies",
    "headers",
    "content",
    "redirectURL",
    "headersSize",
    "bodySize",
}


@pytest.mark.integration
def test_proxy_har_export_is_spec_compliant_har_1_2(tmp_path: Path) -> None:
    """The exported HAR must be valid HAR 1.2 a real consumer can open.

    The capture gate only checks entry_count and that a file exists; it never
    proved the file is loadable HAR. The old export emitted just method/url and
    status/mimeType, so Chrome's Import HAR, haralyzer and har-validator would
    all reject it. Route a GET with a query string through the proxy, export,
    then parse the file and assert the whole log shape: a versioned creator, and
    an entry for the request whose startedDateTime is ISO 8601, whose request
    carries the parsed queryString and real headers, and whose response carries
    headers, a status, and the origin's body as content.text -- the fields that
    make the artifact useful, not merely present. skip != pass without mitmproxy.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy HAR Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("har", host="127.0.0.1", port=proxy_port)
    try:
        with _origin_site() as origin:
            target = f"{origin}/hello?q=1&x=2"
            handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
            opener = urllib.request.build_opener(handler)
            # Send a Cookie header so the HAR must parse request cookies too.
            request = urllib.request.Request(target, headers={"Cookie": "sid=abc; theme=dark"})
            with opener.open(request, timeout=15.0) as response:
                assert _ORIGIN_MARKER in response.read().decode("utf-8", "replace")

            # A urlencoded form POST so the HAR must parse postData.params.
            post_req = urllib.request.Request(
                f"{origin}/login",
                data=b"user=alice&pw=s3cret",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with opener.open(post_req, timeout=15.0) as post_resp:
                assert _ORIGIN_MARKER in post_resp.read().decode("utf-8", "replace")

            _poll(
                lambda: backend.flows("har", limit=100),
                lambda r: (
                    any("/hello" in str(f.get("url", "")) for f in r["flows"])
                    and any("/login" in str(f.get("url", "")) for f in r["flows"])
                ),
            )
            har_path = tmp_path / "capture.har"
            result = backend.export_har("har", har_path)
            assert result["entry_count"] >= 1, result

            doc = json.loads(har_path.read_text(encoding="utf-8"))
            log = doc["log"]
            assert log["version"] == "1.2", log
            assert log["creator"]["name"] == "headless-re-mcp"
            assert log["creator"]["version"], "creator.version is required by HAR"

            hello = next(
                (e for e in log["entries"] if "/hello" in e["request"]["url"]), None
            )
            assert hello is not None, [e["request"]["url"] for e in log["entries"]]
            assert set(hello) >= _REQUIRED_ENTRY, hello
            assert set(hello["request"]) >= _REQUIRED_REQUEST, hello["request"]
            assert set(hello["response"]) >= _REQUIRED_RESPONSE, hello["response"]
            assert set(hello["timings"]) >= {"send", "wait", "receive"}, hello["timings"]

            # startedDateTime is a real ISO 8601 instant with a timezone.
            started = datetime.fromisoformat(hello["startedDateTime"])
            assert started.tzinfo is not None, hello["startedDateTime"]

            assert hello["request"]["method"] == "GET"
            # The query string was parsed out of the URL, not dropped.
            qs = {p["name"]: p["value"] for p in hello["request"]["queryString"]}
            assert qs.get("q") == "1" and qs.get("x") == "2", hello["request"]["queryString"]
            # A real forwarded request carries request headers (Host at least).
            assert hello["request"]["headers"], hello["request"]
            names = {h["name"].lower() for h in hello["request"]["headers"]}
            assert "host" in names, names

            # Request cookies are parsed from the Cookie header we sent.
            req_cookies = {c["name"]: c["value"] for c in hello["request"]["cookies"]}
            assert req_cookies.get("sid") == "abc", hello["request"]["cookies"]
            assert req_cookies.get("theme") == "dark", hello["request"]["cookies"]

            resp = hello["response"]
            assert resp["status"] == 200, resp
            assert resp["headers"], resp
            assert _ORIGIN_MARKER in resp["content"].get("text", ""), resp["content"]
            assert resp["content"]["size"] > 0, resp["content"]
            # Response cookies are parsed from the origin's Set-Cookie, attributes
            # and all.
            resp_cookie = next(
                (c for c in resp["cookies"] if c["name"] == _ORIGIN_COOKIE_NAME), None
            )
            assert resp_cookie is not None, resp["cookies"]
            assert resp_cookie["value"] == _ORIGIN_COOKIE_VALUE, resp_cookie
            assert resp_cookie.get("httpOnly") is True, resp_cookie

            # The form POST's body is parsed into postData.params, not left as an
            # opaque text blob (params and text are mutually exclusive in HAR).
            login = next(
                (e for e in log["entries"] if "/login" in e["request"]["url"]), None
            )
            assert login is not None, [e["request"]["url"] for e in log["entries"]]
            post = login["request"].get("postData")
            assert post is not None, login["request"]
            assert "text" not in post, post
            form = {p["name"]: p["value"] for p in post["params"]}
            assert form == {"user": "alice", "pw": "s3cret"}, post["params"]
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_flow_get_on_an_unknown_id_is_a_clean_not_found() -> None:
    """Asking for a flow that was never captured must be a structured miss."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("missing-flow", host="127.0.0.1", port=port)
    try:
        with pytest.raises(ProxyError) as info:
            backend.flow_get("missing-flow", "no-such-flow", Path("/tmp"))
        assert info.value.code == "not_found", info.value.code
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_replay_resends_a_captured_flow_to_its_origin() -> None:
    """proxy.replay must actually re-issue a captured request to its origin.

    Capturing a flow and replaying it is the line's active capability (as
    opposed to passive recording), and nothing proved the replayed request ever
    left the proxy. A counting origin is the witness: route one GET through the
    proxy (origin sees it once), replay the captured flow, and assert the origin
    is hit a second time and a second flow is recorded. skip != pass without
    mitmproxy.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("replay", host="127.0.0.1", port=proxy_port)
    try:
        with _counting_origin() as origin:
            host, port = origin.server_address
            target = f"http://{host}:{port}/hi"
            handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
            opener = urllib.request.build_opener(handler)
            with opener.open(target, timeout=15.0) as response:
                response.read()
            assert origin.hits == 1, origin.hits

            listing = _poll(
                lambda: backend.flows("replay", limit=100),
                lambda r: any(str(f.get("url", "")).endswith("/hi") for f in r["flows"]),
            )
            hits = [f for f in listing["flows"] if str(f.get("url", "")).endswith("/hi")]
            assert hits, listing["flows"]

            result = backend.replay("replay", str(hits[0]["id"]))
            assert result["replayed"] is True, result

            # The origin -- not the client -- must witness the re-issued request.
            resent = _poll(lambda: origin.hits, lambda n: n >= 2)
            assert resent >= 2, resent
            total = _poll(
                lambda: backend.flows("replay", limit=100)["total"], lambda n: n >= 2
            )
            assert total >= 2, total
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_replay_on_an_unknown_id_is_a_clean_not_found() -> None:
    """Replaying a flow that was never captured must be a structured miss."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("replay-missing", host="127.0.0.1", port=port)
    try:
        with pytest.raises(ProxyError) as info:
            backend.replay("replay-missing", "no-such-flow")
        assert info.value.code == "not_found", info.value.code
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_start_provisions_a_trustable_ca_certificate() -> None:
    """Starting the proxy must yield a real CA cert callers can install to trust it.

    Intercepting HTTPS depends on the client trusting mitmproxy's CA, which the
    backend surfaces via ca_cert_path(). Prove that what comes back is a parseable
    X.509 CA certificate (basicConstraints CA:TRUE) -- not merely that some file
    exists -- so the "install this to intercept TLS" story is real. The CA is a
    machine-global mitmproxy artifact, so this asserts its validity rather than
    deleting a developer's real ~/.mitmproxy. skip != pass without mitmproxy.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy CA Gate not run (skip != pass)")
    from cryptography import x509

    backend = ProxyBackend()
    port = _free_port()
    backend.start("ca-gate", host="127.0.0.1", port=port)
    try:
        ca = _poll(lambda: backend.ca_cert_path(), lambda p: p is not None)
        assert ca is not None, "proxy start did not provision a CA certificate"
        assert ca.is_file(), ca
        cert = x509.load_pem_x509_certificate(ca.read_bytes())
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert basic.ca is True, "mitmproxy CA cert is not marked as a CA"
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_start_means_listening_and_stop_releases_the_port() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    started = backend.start("gate-session", host="127.0.0.1", port=port)
    try:
        assert started["running"] is True
        assert started["port"] == port
        # start() must not return before the socket actually accepts.
        assert _port_accepts("127.0.0.1", port, timeout=1.0) is True

        status = backend.status("gate-session")
        assert status["running"] is True
        assert status["flow_count"] == 0
        assert status["retained_max"] > 0
    finally:
        stopped = backend.stop("gate-session")

    assert stopped["stopped"] is True
    assert backend.status("gate-session") == {"running": False}

    # The listener must actually go away, or the next run cannot rebind.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if not _port_accepts("127.0.0.1", port, timeout=0.25):
            break
        time.sleep(0.1)
    else:
        pytest.fail("proxy port was still accepting connections after stop")


@pytest.mark.integration
def test_start_on_an_occupied_port_fails_instead_of_reporting_success() -> None:
    """A leftover listener must not be mistaken for our own healthy capture."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    squatter = socket.socket()
    squatter.bind(("127.0.0.1", 0))
    squatter.listen(1)
    port = int(squatter.getsockname()[1])
    try:
        with pytest.raises(ProxyError) as info:
            backend.start("gate-occupied", host="127.0.0.1", port=port)
        assert info.value.code == "invalid_state"
        # A refused start must leave no half-registered session behind.
        assert backend.status("gate-occupied") == {"running": False}
    finally:
        squatter.close()
        backend.stop("gate-occupied")


@pytest.mark.integration
def test_two_sessions_cannot_silently_share_one_port() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("first", host="127.0.0.1", port=port)
    try:
        with pytest.raises(ProxyError):
            backend.start("second", host="127.0.0.1", port=port)
        assert backend.status("first")["running"] is True
        assert backend.status("second") == {"running": False}
    finally:
        backend.close_all()


@pytest.mark.integration
def test_close_all_releases_every_running_capture() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    ports = [_free_port(), _free_port()]
    for index, port in enumerate(ports):
        backend.start(f"session-{index}", host="127.0.0.1", port=port)
    backend.close_all()
    for index, port in enumerate(ports):
        assert backend.status(f"session-{index}") == {"running": False}
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if not _port_accepts("127.0.0.1", port, timeout=0.25):
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"port {port} still accepting after close_all")


# --- WebSocket-through-proxy gate ------------------------------------------
# A hand-rolled RFC 6455 origin plus a proxy-aware client, so the gate proves
# mitmproxy actually records WebSocket frames end to end without pulling in a
# websocket dependency. mitmproxy bridges the two legs (it does its own
# handshake with the client and with the origin), so each side just needs a
# valid handshake and framing.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_WS_PATH = "/ws"
_WS_CLIENT_TEXT = "proxy-ws-client-9449"
_WS_TEXT_REPLY = "proxy-ws-server-9449"
_WS_BINARY_REPLY = b"\x00\x01\x02\x03\xfd\xfe\xff"


def _ws_frame(opcode: int, payload: bytes, *, mask: bool = False) -> bytes:
    """Build one WebSocket frame; masked when acting as the client leg."""
    out = bytes([0x80 | opcode])
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if length < 126:
        out += bytes([mask_bit | length])
    elif length < 65536:
        out += bytes([mask_bit | 126]) + length.to_bytes(2, "big")
    else:
        out += bytes([mask_bit | 127]) + length.to_bytes(8, "big")
    if mask:
        key = os.urandom(4)
        out += key
        payload = bytes(byte ^ key[i % 4] for i, byte in enumerate(payload))
    return out + payload


def _ws_read(rfile: Any) -> tuple[int | None, bytes]:
    """Read one frame (masked or not); returns (opcode, payload)."""
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
    key = rfile.read(4) if masked else b""
    data = rfile.read(length)
    if masked:
        data = bytes(byte ^ key[i % 4] for i, byte in enumerate(data))
    return opcode, data


class _WsOriginHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.send_response(426)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
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
        # mitmproxy connects as the client on this leg, so its frames are masked;
        # _ws_read handles that. Push a text and a binary reply back.
        self.wfile.write(_ws_frame(0x1, _WS_TEXT_REPLY.encode()))
        self.wfile.write(_ws_frame(0x2, _WS_BINARY_REPLY))
        self.wfile.flush()
        self.connection.settimeout(8.0)
        with contextlib.suppress(Exception):
            while True:
                opcode, _data = _ws_read(self.rfile)
                if opcode is None or opcode in (0x1, 0x8):
                    break
        with contextlib.suppress(Exception):
            self.wfile.write(_ws_frame(0x8, b""))
            self.wfile.flush()


@contextlib.contextmanager
def _ws_origin() -> Iterator[tuple[str, int]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WsOriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield host, int(port)
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _drive_ws_through_proxy(proxy_port: int, origin_host: str, origin_port: int) -> None:
    """Open a ws:// through the forward proxy, send a frame, read the replies."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0)
    sock.settimeout(10.0)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        # Absolute-form request line is how a forward proxy is asked to reach the
        # origin; mitmproxy upgrades it to a WebSocket flow.
        handshake = (
            f"GET http://{origin_host}:{origin_port}{_WS_PATH} HTTP/1.1\r\n"
            f"Host: {origin_host}:{origin_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(handshake.encode())
        rfile = sock.makefile("rb")
        status_line = rfile.readline()
        assert b"101" in status_line, status_line
        while True:  # drain the rest of the handshake response headers
            line = rfile.readline()
            if line in (b"\r\n", b"", b"\n"):
                break
        # Client leg frames must be masked.
        sock.sendall(_ws_frame(0x1, _WS_CLIENT_TEXT.encode(), mask=True))
        # Read the two replies the origin pushed (relayed unmasked by the proxy).
        for _ in range(2):
            _ws_read(rfile)
        sock.sendall(_ws_frame(0x8, b"", mask=True))
    finally:
        with contextlib.suppress(Exception):
            sock.close()


@pytest.mark.integration
def test_proxy_captures_websocket_frames_end_to_end(tmp_path: Path) -> None:
    """Prove mitmproxy records WebSocket frames the proxy line can surface.

    The proxy captured HTTP flows but ignored WebSocket traffic, so a socket
    routed through it looked like a lone 101 handshake. Route a real ws:// through
    the running proxy: the client sends one text frame and the origin pushes back
    a text and a binary frame; proxy.flows must then flag the flow as a WebSocket
    with a message count, and proxy.flow.get must return the frames with their
    direction, type and payloads (binary as base64). proxy.ws.frames must then
    page the same conversation via offset/limit. skip != pass without mitmproxy.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy WebSocket Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("ws", host="127.0.0.1", port=proxy_port)
    try:
        with _ws_origin() as (origin_host, origin_port):
            _drive_ws_through_proxy(proxy_port, origin_host, origin_port)

            def _ws_flow() -> dict[str, Any] | None:
                listing = backend.flows("ws", limit=100)
                return next(
                    (
                        f
                        for f in listing["flows"]
                        if str(f.get("url", "")).endswith(_WS_PATH)
                        and f.get("websocket")
                        and int(f.get("ws_messages", 0)) >= 3
                    ),
                    None,
                )

            flow = _poll(_ws_flow, lambda f: f is not None, tries=80)
            assert flow is not None, "no WebSocket flow with frames was captured"

            detail = backend.flow_get("ws", str(flow["id"]), tmp_path)
            assert "websocket" in detail, detail
            frames = detail["websocket"]["messages"]

            sent = [f for f in frames if f["direction"] == "sent"]
            assert any(f["payload"] == _WS_CLIENT_TEXT for f in sent), frames

            recv_text = [
                f for f in frames if f["direction"] == "received" and f["type"] == "text"
            ]
            assert any(f["payload"] == _WS_TEXT_REPLY for f in recv_text), frames

            recv_binary = [
                f for f in frames if f["direction"] == "received" and f["type"] == "binary"
            ]
            assert recv_binary, frames
            assert any(
                base64.b64decode(f["payload"]) == _WS_BINARY_REPLY for f in recv_binary
            ), recv_binary

            # proxy.ws.frames walks the same conversation via offset/limit, so a
            # busy socket whose frames spill past flow.get's inline cap stays
            # fully reachable. Page it one frame at a time and confirm the walk
            # reproduces flow.get's inline frames in order.
            head = backend.ws_frames("ws", str(flow["id"]), offset=0, limit=1)
            assert head["url"].endswith(_WS_PATH)
            assert head["total"] == len(frames)
            assert head["offset"] == 0
            assert head["count"] == 1
            assert head["has_more"] is True
            # A handful of frames is well under the per-flow retention cap, so
            # nothing was evicted.
            assert head["dropped"] == 0
            tail = backend.ws_frames("ws", str(flow["id"]), offset=1, limit=100)
            assert tail["offset"] == 1
            assert tail["count"] == len(frames) - 1
            assert tail["has_more"] is False
            assert tail["dropped"] == 0
            walked = head["frames"] + tail["frames"]
            assert [f["payload"] for f in walked] == [f["payload"] for f in frames]

            # The HAR export carries the socket as DevTools _webSocketMessages,
            # so the captured frames re-import into DevTools.
            har_path = tmp_path / "ws.har"
            backend.export_har("ws", har_path)
            log = json.loads(har_path.read_text(encoding="utf-8"))["log"]
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
        backend.close_all()


# --- proxy capture -> static analysis handoff ------------------------------
# The web line proves a live page's script/module feeds the js/wasm static
# tools; the proxy line must do the same for whatever it forwards. Serve a small
# binary .wasm and a >200 KB JS bundle so flow.get spills both to body_path (the
# wasm because it is binary, the bundle because it is oversized), then feed those
# exact bytes to the static tools.
_JS_BUNDLE_MARKER = "proxy-js-chain-9449"
_ASSET_WASM_PATH = "/module.wasm"
_ASSET_JS_PATH = "/bundle.js"


def _build_proxy_js_bundle() -> str:
    body = ";".join(
        f"function f{i}(a,b){{if(a>b){{return a*{i}+b}}else{{return b-a+{i}}}}}"
        for i in range(9000)
    )
    return f'var __marker="{_JS_BUNDLE_MARKER}";{body};'


_JS_BUNDLE = _build_proxy_js_bundle()


class _AssetOriginHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _ASSET_WASM_PATH:
            body, ctype = _WASM_FIXTURE.read_bytes(), "application/wasm"
        elif self.path == _ASSET_JS_PATH:
            body, ctype = _JS_BUNDLE.encode("utf-8"), "application/javascript"
        else:
            body, ctype = b"ok", "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _asset_origin() -> Iterator[str]:
    """A loopback origin that serves a binary .wasm and a large JS bundle."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AssetOriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


@pytest.mark.integration
def test_proxy_captured_bodies_feed_the_static_analysis_lines(tmp_path: Path) -> None:
    """A body captured through the proxy must feed the js/wasm static tools.

    This is the proxy-side twin of the web capture -> static handoff: whatever
    the proxy records has to reach the analysis tools as real bytes, not a lossy
    inline preview. Route two GETs through the running proxy -- a small binary
    .wasm and a >200 KB JS bundle -- and prove flow.get spills both to body_path
    (the wasm because it is binary, so a utf-8 inline would mangle it; the bundle
    because it is oversized) with the exact bytes. Then feed those paths to
    wasm.decompile and js.deobfuscate: the module decompiles to its named export
    add() and the bundle's marker survives deobfuscation. skip != pass without
    mitmproxy (or the wabt/webcrack tools for the final leg).
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy static-handoff Gate not run (skip != pass)")
    if not _WASM_FIXTURE.is_file():
        pytest.skip(f"wasm fixture missing: {_WASM_FIXTURE} — skip != pass")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("static-handoff", host="127.0.0.1", port=proxy_port)
    try:
        with _asset_origin() as origin:
            handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
            opener = urllib.request.build_opener(handler)
            for path in (_ASSET_WASM_PATH, _ASSET_JS_PATH):
                with opener.open(f"{origin}{path}", timeout=15.0) as resp:
                    resp.read()

            def _flow_for(suffix: str) -> dict[str, Any] | None:
                listing = backend.flows("static-handoff", limit=200)
                return next(
                    (f for f in listing["flows"] if str(f.get("url", "")).endswith(suffix)),
                    None,
                )

            wasm_flow = _poll(
                lambda: _flow_for(_ASSET_WASM_PATH), lambda f: f is not None, tries=80
            )
            js_flow = _poll(
                lambda: _flow_for(_ASSET_JS_PATH), lambda f: f is not None, tries=80
            )
            assert wasm_flow is not None, "no /module.wasm flow was captured"
            assert js_flow is not None, "no /bundle.js flow was captured"

            # The binary .wasm must spill to a file with the exact bytes, not a
            # utf-8-replaced mangling that no wasm tool could parse.
            wasm_detail = backend.flow_get("static-handoff", str(wasm_flow["id"]), tmp_path)
            assert "body" not in wasm_detail["response"], wasm_detail["response"]
            wasm_path = Path(str(wasm_detail["response"]["body_path"]))
            assert wasm_path.read_bytes() == _WASM_FIXTURE.read_bytes()
            assert wasm_path.read_bytes()[:4] == b"\x00asm", wasm_path.read_bytes()[:8]

            # The large JS bundle must spill too (over the 200 KB inline cap).
            js_detail = backend.flow_get("static-handoff", str(js_flow["id"]), tmp_path)
            assert "body" not in js_detail["response"], js_detail["response"]
            js_path = Path(str(js_detail["response"]["body_path"]))
            assert _JS_BUNDLE_MARKER in js_path.read_text(encoding="utf-8")

            # The seam: the captured artifacts feed the static tools losslessly.
            if WasmClient().available:
                dec = WasmClient().decompile(wasm_path, spill_dir=tmp_path)
                assert "function add" in (dec.get("code") or ""), dec

            if JsClient().available:
                deob = JsClient().deobfuscate(js_path, spill_dir=tmp_path)
                code = deob.get("code") or ""
                # webcrack may cut the inline preview and spill the rest; the
                # marker is the first statement, but fall back to the artifact so
                # the assertion is about the whole output, not just the preview.
                if _JS_BUNDLE_MARKER not in code and deob.get("artifact_path"):
                    code = Path(str(deob["artifact_path"])).read_text(encoding="utf-8")
                assert _JS_BUNDLE_MARKER in code, "marker lost through deobfuscation"
    finally:
        backend.close_all()
