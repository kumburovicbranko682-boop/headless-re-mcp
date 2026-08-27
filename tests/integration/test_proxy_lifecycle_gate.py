"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _port_accepts


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    """A tiny origin the proxied request can actually reach on localhost."""

    def do_GET(self) -> None:  # noqa: N802 - http.server dispatch name
        body = b"proxy-gate-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep the gate output quiet
        return


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
def test_a_request_through_the_proxy_is_captured_as_a_flow(tmp_path: Path) -> None:
    """The proxy's reason to exist: traffic through it is recorded and retrievable.

    The other gates prove the port opens and closes; this pushes a real GET
    through the proxy and checks the interception path -- the flow shows up in
    flows(), flow_get() returns its body, and export_har() writes it out -- so
    the capture surface is exercised, not just the socket.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")

    origin = http.server.HTTPServer(("127.0.0.1", 0), _OriginHandler)
    origin_port = int(origin.server_address[1])
    origin_thread = threading.Thread(
        target=origin.serve_forever, name="proxy-gate-origin", daemon=True
    )
    origin_thread.start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("capture", host="127.0.0.1", port=proxy_port)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
        )
        target = f"http://127.0.0.1:{origin_port}/gate"
        with opener.open(target, timeout=10.0) as response:
            assert response.read() == b"proxy-gate-ok"

        # mitmproxy records the flow on the response event, which lands just
        # after the client's read returns; poll rather than assume it is there.
        deadline = time.monotonic() + 10.0
        flows: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            flows = backend.flows("capture")["flows"]
            if flows:
                break
            time.sleep(0.1)
        assert flows, "the proxied request was not captured as a flow"

        flow = next(f for f in flows if f["url"] == target)
        assert flow["method"] == "GET"
        assert flow["status"] == 200
        assert flow["host"] == "127.0.0.1"

        detail = backend.flow_get("capture", str(flow["id"]), tmp_path)
        assert detail["request"]["method"] == "GET"
        assert detail["request"]["url"] == target
        assert detail["response"]["status"] == 200
        assert detail["response"]["body"] == "proxy-gate-ok"

        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture", har_path)
        assert exported["entry_count"] >= 1
        har = json.loads(har_path.read_text(encoding="utf-8"))
        urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
        assert target in urls
    finally:
        backend.stop("capture")
        origin.shutdown()
        origin.server_close()


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
