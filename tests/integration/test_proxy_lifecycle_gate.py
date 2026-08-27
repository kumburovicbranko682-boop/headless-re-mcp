"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _port_accepts


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


@contextlib.contextmanager
def _serve_origin(body: bytes) -> Iterator[str]:
    """A throwaway localhost origin the proxy can forward one request to."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # keep pytest output clean
            del args

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/thing"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _get_through_proxy(url: str, proxy_port: int) -> bytes:
    """Fetch a plain-HTTP URL via the proxy, the way a device would be told to."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(url, timeout=10.0) as resp:
        return bytes(resp.read())


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


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
def test_a_request_through_the_proxy_is_captured_read_and_replayed(tmp_path: Path) -> None:
    """Drive the capture data path the lifecycle tests never touch.

    Those prove the port opens and closes, but with flow_count == 0: nothing
    ever traverses the proxy. Route one real HTTP request through it to a
    throwaway origin, then assert the flow is listed with the right
    method/status/url, its body comes back with the expected marker, a HAR
    entry is written, and the flow replays -- the flows / flow.get /
    export_har / replay surface an unattended capture actually depends on.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    marker = b'{"marker": "proxy-capture-gate-marker", "value": 7}'
    backend = ProxyBackend()
    port = _free_port()
    with _serve_origin(marker) as origin_url:
        backend.start("capture", host="127.0.0.1", port=port)
        try:
            body = _get_through_proxy(origin_url, port)
            assert b"proxy-capture-gate-marker" in body  # the client itself got it

            assert _wait_until(lambda: backend.flows("capture")["total"] >= 1), (
                "no flow was recorded after a request traversed the proxy"
            )

            listing = backend.flows("capture")
            flow = listing["flows"][0]
            assert flow["method"] == "GET"
            assert flow["status"] == 200
            assert "/api/thing" in flow["url"]

            detail = backend.flow_get("capture", flow["id"], tmp_path)
            assert detail["request"]["method"] == "GET"
            assert "proxy-capture-gate-marker" in str(detail["response"]["body"])

            har = backend.export_har("capture", tmp_path / "capture.har")
            assert har["entry_count"] >= 1

            replay = backend.replay("capture", flow["id"])
            assert replay["replayed"] is True
        finally:
            backend.stop("capture")


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
