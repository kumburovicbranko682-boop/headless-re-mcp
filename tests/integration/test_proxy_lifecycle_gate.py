"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _port_accepts


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


_ORIGIN_BODY = b'{"ok":true,"who":"origin"}'


@contextmanager
def _origin_server() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
            self.end_headers()
            self.wfile.write(_ORIGIN_BODY)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = b'{"stored":true}'
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/thing"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


_GZIP_PLAINTEXT = b'{"marker":"gzip-gate","numbers":[1,2,3,4,5],"nested":{"a":true}}'


@contextmanager
def _gzip_origin_server() -> Iterator[str]:
    """An origin that gzips its response, like most real APIs on the wire."""
    import gzip as _gz

    compressed = _gz.compress(_GZIP_PLAINTEXT)

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(compressed)))
            self.end_headers()
            self.wfile.write(compressed)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/gz"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


_TLS_ORIGIN_BODY = b'{"ok":true,"tls":true,"who":"origin"}'


@contextmanager
def _tls_origin_server() -> Iterator[str]:
    """A self-signed HTTPS origin, like the servers this proxy really targets.

    Uses cryptography (a mitmproxy dependency, so present whenever the proxy is)
    to mint a throwaway 127.0.0.1 certificate. A public CA would defeat the
    point: the whole reason ssl_insecure exists is upstreams that do not chain
    to one.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = Path(tempfile.mkdtemp()) / "origin.pem"
    pem.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_TLS_ORIGIN_BODY)))
            self.end_headers()
            self.wfile.write(_TLS_ORIGIN_BODY)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pem))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/api/thing"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@contextmanager
def _counting_origin_server() -> Iterator[tuple[str, dict[str, int]]]:
    """An HTTP origin that tallies GETs, so a replay can be proven to reach it."""
    hits = {"count": 0}

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            hits["count"] += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
            self.end_headers()
            self.wfile.write(_ORIGIN_BODY)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/thing", hits
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _poll(predicate: Callable[[], Any], *, timeout: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout
    found = predicate()
    while not found and time.monotonic() < deadline:
        time.sleep(0.1)
        found = predicate()
    return found


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


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
def test_proxy_actually_intercepts_and_records_a_request() -> None:
    """Start/stop is not enough: the point of the proxy is to record traffic.

    Drive a real HTTP request through the running proxy to a local origin and
    assert the flow is captured and that flow_get returns the exact response
    body. This is the interception contract Web and Android both rely on, and
    nothing exercised it live before -- the lifecycle gate never sent a byte.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy interception Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _origin_server() as origin_url:
        backend.start("gate-capture", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            with opener.open(origin_url, timeout=10) as response:
                assert response.status == 200
                assert response.read() == _ORIGIN_BODY

            def _captured() -> dict[str, Any] | None:
                listing = backend.flows("gate-capture")
                for flow in listing["flows"]:
                    if str(flow.get("url", "")).endswith("/api/thing"):
                        return flow
                return None

            flow = _poll(_captured)
            assert flow is not None, "the request through the proxy was never recorded"
            assert flow["method"] == "GET"
            assert flow["status"] == 200

            detail = backend.flow_get("gate-capture", flow["id"], Path(tempfile.mkdtemp()))
            assert detail["request"]["method"] == "GET"
            assert detail["response"]["status"] == 200
            assert detail["response"]["body"] == _ORIGIN_BODY.decode("utf-8")

            # The request body is the point of most captures; drive a POST with
            # a payload and assert flow_get hands it back, not just the response.
            post_url = origin_url.rsplit("/", 1)[0] + "/login"
            payload = b'{"user":"alice","token":"s3cr3t"}'
            post = urllib.request.Request(
                post_url, data=payload, headers={"Content-Type": "application/json"}
            )
            with opener.open(post, timeout=10) as response:
                assert response.status == 201

            def _captured_post() -> dict[str, Any] | None:
                for flow in backend.flows("gate-capture")["flows"]:
                    if str(flow.get("url", "")).endswith("/login"):
                        return flow
                return None

            post_flow = _poll(_captured_post)
            assert post_flow is not None, "the POST through the proxy was never recorded"
            assert post_flow["method"] == "POST"
            assert post_flow.get("has_request_body") is True
            post_detail = backend.flow_get(
                "gate-capture", post_flow["id"], Path(tempfile.mkdtemp())
            )
            assert post_detail["request"]["method"] == "POST"
            assert post_detail["request"]["size"] == len(payload)
            assert post_detail["request"]["body"] == payload.decode("utf-8")
            assert post_detail["response"]["status"] == 201
        finally:
            backend.stop("gate-capture")


@pytest.mark.integration
def test_proxy_flows_filter_narrows_a_capture() -> None:
    """On a real capture, filtering must find one request without paging by hand.

    Drive a GET and a POST through the proxy, then assert the method, url and
    status filters each narrow the live capture to the intended flow, that the
    reply reports filtered/unfiltered_total, and that a non-matching flow is
    absent from the filtered page.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy filter Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _origin_server() as origin_url:
        backend.start("gate-filter", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            base = origin_url.rsplit("/", 1)[0]  # .../api
            with opener.open(origin_url, timeout=10) as response:  # GET /api/thing
                assert response.status == 200
            post = urllib.request.Request(
                base + "/login",
                data=b'{"user":"alice"}',
                headers={"Content-Type": "application/json"},
            )
            with opener.open(post, timeout=10) as response:  # POST /api/login -> 201
                assert response.status == 201

            assert _poll(lambda: backend.flows("gate-filter")["total"] >= 2), (
                "both requests through the proxy were never recorded"
            )

            posts = backend.flows("gate-filter", method="post")  # case-insensitive
            assert posts["filtered"] is True
            assert posts["unfiltered_total"] >= 2
            assert posts["total"] == len(posts["flows"])
            assert posts["count"] >= 1
            assert all(flow["method"] == "POST" for flow in posts["flows"])
            assert any(str(f.get("url", "")).endswith("/login") for f in posts["flows"])
            assert not any(str(f.get("url", "")).endswith("/thing") for f in posts["flows"])

            things = backend.flows("gate-filter", url_contains="/thing")
            assert things["count"] >= 1
            assert all("/thing" in str(f.get("url", "")) for f in things["flows"])

            created = backend.flows("gate-filter", status=201)
            assert created["count"] >= 1
            assert all(flow.get("status") == 201 for flow in created["flows"])
            assert any(str(f.get("url", "")).endswith("/login") for f in created["flows"])
        finally:
            backend.stop("gate-filter")


@pytest.mark.integration
def test_proxy_stats_summarizes_a_live_capture() -> None:
    """On a real capture, stats must fold the ring into an accurate summary.

    Drive a GET (200) and a POST with a body (201) through the proxy, then assert
    proxy.stats counts both methods, files both under the 2xx class, ranks the
    origin host, and tallies the request body -- the triage view a caller reads
    before deciding what to filter for, without paging the whole log.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy stats Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _origin_server() as origin_url:
        backend.start("gate-stats", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            base = origin_url.rsplit("/", 1)[0]  # .../api
            with opener.open(origin_url, timeout=10) as response:  # GET -> 200
                assert response.status == 200
            post = urllib.request.Request(
                base + "/login",
                data=b'{"user":"alice"}',
                headers={"Content-Type": "application/json"},
            )
            with opener.open(post, timeout=10) as response:  # POST -> 201
                assert response.status == 201

            assert _poll(lambda: backend.flows("gate-stats")["total"] >= 2), (
                "both requests through the proxy were never recorded"
            )
            stats = backend.stats("gate-stats")
            assert stats["total"] >= 2
            assert stats["by_method"].get("GET", 0) >= 1
            assert stats["by_method"].get("POST", 0) >= 1
            # 200 and 201 both fall in the 2xx class.
            assert stats["by_status_class"].get("2xx", 0) >= 2
            assert stats["with_request_body"] >= 1
            hosts = {row["host"] for row in stats["top_hosts"]}
            assert "127.0.0.1" in hosts
            assert stats["host_count"] >= 1
            # There is no per-flow listing on the summary.
            assert "flows" not in stats
        finally:
            backend.stop("gate-stats")


@pytest.mark.integration
def test_proxy_decodes_a_gzip_response_body() -> None:
    """A gzip'd upstream response must reach the analyst as the payload.

    Most real APIs gzip their responses; capturing raw_content handed back
    compressed bytes, so the captured body read as binary garbage. Drive a
    real gzip response through the proxy and assert flow_get returns the
    decoded JSON, size is the decoded length, and content_encoding records the
    wire encoding.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy gzip Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _gzip_origin_server() as origin_url:
        backend.start("gate-gzip", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            # urllib does not gunzip on its own, so the client sees the raw
            # compressed bytes -- proof the origin really encoded on the wire.
            req = urllib.request.Request(origin_url, headers={"Accept-Encoding": "gzip"})
            with opener.open(req, timeout=10) as response:
                raw = response.read()
            assert raw[:2] == b"\x1f\x8b", "the origin did not actually gzip"
            assert raw != _GZIP_PLAINTEXT

            def _captured() -> dict[str, Any] | None:
                for flow in backend.flows("gate-gzip")["flows"]:
                    if str(flow.get("url", "")).endswith("/api/gz"):
                        return flow
                return None

            flow = _poll(_captured)
            assert flow is not None, "the gzip request through the proxy was never recorded"
            detail = backend.flow_get("gate-gzip", flow["id"], Path(tempfile.mkdtemp()))
            assert detail["response"]["body"] == _GZIP_PLAINTEXT.decode("utf-8")
            assert detail["response"]["size"] == len(_GZIP_PLAINTEXT)
            assert detail["response"]["content_encoding"] == "gzip"
        finally:
            backend.stop("gate-gzip")


@pytest.mark.integration
def test_proxy_records_a_failed_upstream_flow() -> None:
    """A request whose upstream fails must be recorded, not vanish.

    mitmproxy delivers a refused/failed upstream through the error hook, never
    response, so before this the flow was dropped entirely: the capture looked
    empty even though a request was attempted, and the failure reason was lost.
    Route a request through the proxy to a loopback port that is bound but never
    listening (connection refused) and assert the flow is recorded failed with
    an error message and a null status, and that flow_get surfaces the failure.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy failure Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dead.bind(("127.0.0.1", 0))
    dead_port = int(dead.getsockname()[1])  # bound, never listening -> refused
    try:
        backend.start("gate-fail", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            # The upstream is refused, so the proxy answers 502 / the request
            # raises; either way the flow must be recorded as failed.
            with contextlib.suppress(Exception):
                opener.open(f"http://127.0.0.1:{dead_port}/dead", timeout=10).read()

            def _failed() -> dict[str, Any] | None:
                for flow in backend.flows("gate-fail")["flows"]:
                    if str(flow.get("url", "")).endswith("/dead") and flow.get("failed"):
                        return flow
                return None

            flow = _poll(_failed, timeout=15.0)
            assert flow is not None, "the failed request through the proxy was never recorded"
            assert flow["failed"] is True
            assert flow["status"] is None
            assert isinstance(flow.get("error"), str)
            assert flow["error"], "the failure reason was dropped"

            detail = backend.flow_get("gate-fail", flow["id"], Path(tempfile.mkdtemp()))
            assert detail["failed"] is True
            assert detail["error"]
            assert detail["response"]["status"] is None
        finally:
            backend.stop("gate-fail")
    finally:
        dead.close()


@pytest.mark.integration
def test_proxy_decrypts_https_when_ssl_insecure_is_set() -> None:
    """HTTPS interception is the point of a MITM proxy, and it had no live test.

    Against a self-signed upstream -- the norm for the apps and dev servers this
    tool targets -- mitmproxy's default upstream verification returns a 502 and
    records nothing, so the capture looks empty. ssl_insecure turns that into a
    real decrypted flow: the client (trusting the proxy CA) gets 200 and
    flow_get returns the plaintext body the proxy read off the TLS stream.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy HTTPS Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _tls_origin_server() as origin_url:
        started = backend.start("gate-tls", host="127.0.0.1", port=port, ssl_insecure=True)
        assert started["ssl_insecure"] is True
        try:
            ca = _poll(backend.ca_cert_path)
            assert ca is not None, "mitmproxy never wrote its CA certificate"
            tls_ctx = ssl.create_default_context(cafile=str(ca))
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{port}"}),
                urllib.request.HTTPSHandler(context=tls_ctx),
            )
            with opener.open(origin_url, timeout=15) as response:
                assert response.status == 200
                assert response.read() == _TLS_ORIGIN_BODY

            def _captured() -> dict[str, Any] | None:
                for flow in backend.flows("gate-tls")["flows"]:
                    if str(flow.get("url", "")).startswith("https://") and str(
                        flow.get("url", "")
                    ).endswith("/api/thing"):
                        return flow
                return None

            flow = _poll(_captured)
            assert flow is not None, "the HTTPS request was intercepted but never recorded"
            assert flow["status"] == 200
            detail = backend.flow_get("gate-tls", flow["id"], Path(tempfile.mkdtemp()))
            assert detail["request"]["url"].startswith("https://")
            assert detail["response"]["body"] == _TLS_ORIGIN_BODY.decode("utf-8")
        finally:
            backend.stop("gate-tls")


@pytest.mark.integration
def test_proxy_replay_reissues_a_captured_request_to_the_origin() -> None:
    """replay is a first-class RE move -- re-send a captured call -- with no test.

    mitmproxy's replay.client command changes across versions and runs on the
    proxy's own event loop, so "did it actually re-hit the server" was never
    verified live. Capture one GET, replay it, and assert the origin receives a
    second request and the replayed call is itself recorded.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _counting_origin_server() as (origin_url, hits):
        backend.start("gate-replay", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            with opener.open(origin_url, timeout=10) as response:
                assert response.status == 200

            flow = _poll(
                lambda: next(
                    (
                        f
                        for f in backend.flows("gate-replay")["flows"]
                        if str(f.get("url", "")).endswith("/api/thing")
                    ),
                    None,
                )
            )
            assert flow is not None, "the original request was never recorded"
            assert hits["count"] == 1

            result = backend.replay("gate-replay", flow["id"])
            assert result["replayed"] is True
            assert result["flow_id"] == flow["id"]

            assert _poll(lambda: hits["count"] >= 2, timeout=10.0), (
                "replay reported success but the origin never got the second request"
            )
            # the replayed request is itself intercepted, so the capture grows.
            assert _poll(lambda: backend.flows("gate-replay")["total"] >= 2, timeout=10.0)
        finally:
            backend.stop("gate-replay")


@pytest.mark.integration
def test_proxy_export_har_serialises_the_capture(tmp_path: Path) -> None:
    """export_har turns the live capture into a HAR log, but had no live test.

    Capture one request, export, and assert a valid HAR 1.2 log lands on disk
    with an entry that names the request's method and URL -- the shape any HAR
    viewer or downstream replay tool expects.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy HAR Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _counting_origin_server() as (origin_url, _hits):
        backend.start("gate-har", host="127.0.0.1", port=port)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
            )
            with opener.open(origin_url, timeout=10) as response:
                assert response.status == 200
            assert _poll(lambda: backend.flows("gate-har")["total"] >= 1)

            out = tmp_path / "capture.har"
            result = backend.export_har("gate-har", out)
            assert result["entry_count"] >= 1
            assert out.is_file()
            log = json.loads(out.read_text(encoding="utf-8"))["log"]
            assert log["version"] == "1.2"
            assert any(
                str(entry["request"]["url"]).endswith("/api/thing")
                and entry["request"]["method"] == "GET"
                for entry in log["entries"]
            ), "the captured GET is missing from the HAR"
        finally:
            backend.stop("gate-har")


_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_accept(key: str) -> str:
    digest = hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455
    return base64.b64encode(digest).decode("ascii")


def _ws_recv_frame(sock: socket.socket) -> tuple[int, bytes] | None:
    header = sock.recv(2)
    if len(header) < 2:
        return None
    opcode = header[0] & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", sock.recv(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", sock.recv(8))[0]
    mask = sock.recv(4) if masked else b""
    data = b""
    while len(data) < length:
        data += sock.recv(length - len(data))
    if masked:
        data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
    return opcode, data


def _ws_send_frame(sock: socket.socket, payload: bytes, *, mask: bool, opcode: int = 0x1) -> None:
    length = len(payload)
    header = bytes([0x80 | opcode])
    marker = length if length < 126 else (126 if length < 65536 else 127)
    header += bytes([marker | (0x80 if mask else 0)])
    if 126 <= length < 65536:
        header += struct.pack(">H", length)
    elif length >= 65536:
        header += struct.pack(">Q", length)
    if mask:
        key = os.urandom(4)
        header += key
        payload = bytes(payload[i] ^ key[i % 4] for i in range(length))
    sock.sendall(header + payload)


@contextmanager
def _ws_echo_server() -> Iterator[int]:
    """A raw WebSocket echo server (no third-party dependency) on a free port."""
    ready = threading.Event()
    holder: dict[str, int] = {}

    def serve() -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        holder["port"] = int(listener.getsockname()[1])
        ready.set()
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(1024)
            if not chunk:
                return
            request += chunk
        key = ""
        for line in request.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].decode().strip()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {_ws_accept(key)}\r\n\r\n"
            ).encode()
        )
        while True:
            frame = _ws_recv_frame(conn)
            if frame is None or frame[0] == 0x8:
                break
            _ws_send_frame(conn, b"echo:" + frame[1], mask=False)
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(timeout=5.0)
    try:
        yield holder["port"]
    finally:
        thread.join(timeout=1.0)


@pytest.mark.integration
def test_proxy_captures_websocket_frames() -> None:
    """WebSocket frames were dropped -- only the 101 handshake was recorded.

    A MITM proxy that cannot see WebSocket traffic is blind to every realtime
    app (chat, trading, game and streaming APIs), so this drives a real ws://
    upgrade and duplex frames through the proxy and asserts flow.get returns the
    frames with direction and payload, and the summary flags the socket.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy WebSocket Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    with _ws_echo_server() as origin_port:
        backend.start("gate-ws", host="127.0.0.1", port=port)
        client = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            client.sendall(
                (
                    f"GET http://127.0.0.1:{origin_port}/socket HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{origin_port}\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
                ).encode()
            )
            handshake = b""
            while b"\r\n\r\n" not in handshake:
                handshake += client.recv(1024)
            assert b"101" in handshake.split(b"\r\n")[0], handshake[:80]

            _ws_send_frame(client, b'{"hello":"ws"}', mask=True)
            reply = _ws_recv_frame(client)
            assert reply is not None and reply[1] == b'echo:{"hello":"ws"}'

            def _ws_flow() -> dict[str, Any] | None:
                for flow in backend.flows("gate-ws")["flows"]:
                    if flow.get("is_websocket"):
                        return flow
                return None

            summary = _poll(_ws_flow)
            assert summary is not None, "no flow was flagged as a WebSocket upgrade"
            assert summary["websocket_messages"] >= 2

            detail = backend.flow_get("gate-ws", summary["id"], Path(tempfile.mkdtemp()))
            websocket = detail.get("websocket")
            assert websocket is not None, "flow.get did not carry the WebSocket frames"
            texts = [(m["from_client"], m["text"]) for m in websocket["messages"]]
            assert (True, '{"hello":"ws"}') in texts, texts
            assert (False, 'echo:{"hello":"ws"}') in texts, texts
        finally:
            client.close()
            backend.stop("gate-ws")


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
