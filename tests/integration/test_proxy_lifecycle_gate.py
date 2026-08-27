"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import socket
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
