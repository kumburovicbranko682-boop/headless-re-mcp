"""Live proxy capture gate: a real HTTP request is intercepted, recorded, read back.

The lifecycle gate (test_proxy_lifecycle_gate.py) proves start/stop/port; it
never sends a request through the proxy, so the actual point of the line -- that
a request routed through it becomes a retrievable flow -- had no live coverage.
This drives the backend exactly as the proxy.* tools do: it stands up a local
origin server, routes one GET through the proxy, and asserts the recorded
summary, the full flow detail (request line + response body) and the HAR export
all reflect what really crossed the wire. It stays plain HTTP so it needs no CA
trust.

skip != pass: it skips only when mitmproxy is genuinely absent.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_ORIGIN_BODY = b"hello-from-origin-42"


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


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
        self.end_headers()
        self.wfile.write(_ORIGIN_BODY)

    def log_message(self, *args: object) -> None:  # keep the test output clean
        return


@contextmanager
def _origin_server() -> Iterator[int]:
    server = HTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


@contextmanager
def _counting_origin_server(hits: list[int]) -> Iterator[int]:
    """Like _origin_server but records how many GETs actually reached the origin."""

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
            hits[0] += 1
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
            self.end_headers()
            self.wfile.write(_ORIGIN_BODY)

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", _free_port()), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _get_through_proxy(proxy_port: int, url: str) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(url, timeout=10) as response:
        return bytes(response.read())


def _wait_for_flow(
    backend: ProxyBackend, session_id: str, *, deadline_s: float = 10.0
) -> list[dict[str, object]]:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        flows = backend.flows(session_id)["flows"]
        if flows:
            return list(flows)
        time.sleep(0.1)
    return []


@pytest.mark.integration
def test_proxy_records_a_real_http_request(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    with _origin_server() as origin_port:
        backend.start("capture", host="127.0.0.1", port=proxy_port)
        try:
            url = f"http://127.0.0.1:{origin_port}/probe"
            # The client really receives the origin's body back through the proxy.
            assert _get_through_proxy(proxy_port, url) == _ORIGIN_BODY

            flows = _wait_for_flow(backend, "capture")
            assert flows, "proxy did not record the request that passed through it"
            summary = flows[0]
            assert summary["method"] == "GET"
            assert summary["url"] == url
            assert summary["status"] == 200
            assert "text/plain" in str(summary["content_type"])

            # The full flow carries the request line and the exact response body.
            detail = backend.flow_get("capture", str(summary["id"]), tmp_path / "flows")
            assert detail["request"]["method"] == "GET"
            assert detail["request"]["url"] == url
            assert detail["response"]["status"] == 200
            assert detail["response"]["size"] == len(_ORIGIN_BODY)
            assert detail["response"]["body"] == _ORIGIN_BODY.decode()

            # HAR export reflects the same single entry.
            har = backend.export_har("capture", tmp_path / "capture.har")
            assert har["entry_count"] == 1
            assert Path(har["path"]).is_file()

            status = backend.status("capture")
            assert status["running"] is True
            assert status["flow_count"] == 1
        finally:
            backend.stop("capture")


@pytest.mark.integration
def test_proxy_flow_get_rejects_an_unknown_id(tmp_path: Path) -> None:
    """Reading a flow that was never captured is a structured not_found, not a crash."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("empty", host="127.0.0.1", port=proxy_port)
    try:
        with pytest.raises(ProxyError) as info:
            backend.flow_get("empty", "no-such-flow", tmp_path / "flows")
        assert info.value.code == "not_found"
    finally:
        backend.stop("empty")


@pytest.mark.integration
def test_proxy_replays_a_captured_flow() -> None:
    """proxy.replay re-issues a captured request; it really reaches the origin again.

    The capture gate proves a request becomes a retrievable flow; replay is the
    next tool and had no live coverage. This captures one GET, replays it, and
    proves the replay crossed the wire -- the origin server counts a second hit
    and the proxy records a second flow -- rather than trusting the replayed=True
    envelope alone. Skips only when mitmproxy is absent (skip != pass).
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    hits = [0]
    with _counting_origin_server(hits) as origin_port:
        backend.start("replay", host="127.0.0.1", port=proxy_port)
        try:
            url = f"http://127.0.0.1:{origin_port}/probe"
            assert _get_through_proxy(proxy_port, url) == _ORIGIN_BODY

            flows = _wait_for_flow(backend, "replay")
            assert flows, "proxy did not record the request to replay"
            assert hits[0] == 1

            result = backend.replay("replay", str(flows[0]["id"]))
            assert result["replayed"] is True

            # The replay genuinely re-hits the origin and is recorded again.
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if hits[0] >= 2 and backend.status("replay")["flow_count"] >= 2:
                    break
                time.sleep(0.1)
            assert hits[0] == 2, "replay did not reach the origin a second time"
            assert backend.status("replay")["flow_count"] == 2
        finally:
            backend.stop("replay")


@pytest.mark.integration
def test_proxy_replay_rejects_an_unknown_id() -> None:
    """Replaying a flow that was never captured is a structured not_found, not a crash."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("noreplay", host="127.0.0.1", port=proxy_port)
    try:
        with pytest.raises(ProxyError) as info:
            backend.replay("noreplay", "no-such-flow")
        assert info.value.code == "not_found"
    finally:
        backend.stop("noreplay")


@pytest.mark.integration
def test_proxy_generates_a_valid_interception_ca() -> None:
    """The CA the proxy would install on a device is real and well-formed.

    HTTPS interception -- and proxy.ca_install_android, which pushes this file to
    a device -- rests entirely on the CA mitmproxy mints on first start. Nothing
    asserted it is actually generated or valid. Start the proxy, then assert
    ca_cert_path finds a file that parses as a self-signed X.509 CA
    (BasicConstraints CA=True). No device needed; mitmproxy pulls in cryptography
    so parsing is always available when the proxy backend is.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy CA Gate not run (skip != pass)")
    from cryptography import x509

    backend = ProxyBackend()
    backend.start("ca", host="127.0.0.1", port=_free_port())
    try:
        ca_path = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            ca_path = backend.ca_cert_path()
            if ca_path is not None:
                break
            time.sleep(0.1)
        assert ca_path is not None, "proxy start did not materialise a CA certificate"
        assert ca_path.is_file()
        cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert basic.ca is True
        assert cert.issuer == cert.subject  # a self-signed root
    finally:
        backend.stop("ca")
