"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import http.server
import socket
import socketserver
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
    BODY = b"hello-proxied-body"
    # Counts every served GET so the replay gate can prove a re-issued flow
    # actually reaches the origin a second time.
    hits = 0
    hits_lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        with _OriginHandler.hits_lock:
            _OriginHandler.hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, *_: object) -> None:
        # The default handler writes every hit to stderr, which turns a passing
        # gate into a wall of noise; the assertions below are the record.
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
def test_proxy_records_a_flow_that_can_be_read_back(tmp_path: Path) -> None:
    """Traffic through the proxy must land in the ring and be retrievable.

    The other gates prove the port lifecycle but never send a request, so the
    recorder addon and the flow read API had no live coverage -- exactly the
    surface a mitmproxy major bump (the flow object's request/response shape)
    would break silently. This drives one real HTTP request through the proxy
    and reads the same flow back, body included.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    origin = socketserver.TCPServer(("127.0.0.1", 0), _OriginHandler)
    origin_port = int(origin.server_address[1])
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    backend = ProxyBackend()
    port = _free_port()
    backend.start("gate-capture", host="127.0.0.1", port=port)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
        )
        with opener.open(f"http://127.0.0.1:{origin_port}/thing", timeout=10) as response:
            assert response.read() == _OriginHandler.BODY

        # The addon records on the response event, which the proxy dispatches on
        # its own loop thread; wait for it rather than assuming it is immediate.
        deadline = time.monotonic() + 5.0
        listing = backend.flows("gate-capture", limit=10)
        while listing["count"] == 0 and time.monotonic() < deadline:
            time.sleep(0.1)
            listing = backend.flows("gate-capture", limit=10)
        assert listing["count"] >= 1, "no flow was recorded for a proxied request"

        summary = listing["flows"][0]
        assert summary["method"] == "GET"
        assert summary["url"].endswith("/thing")
        assert summary["status"] == 200

        detail = backend.flow_get("gate-capture", str(summary["id"]), tmp_path)
        assert detail["request"]["method"] == "GET"
        assert detail["response"]["status"] == 200
        assert detail["response"]["body"] == _OriginHandler.BODY.decode()

        exported = backend.export_har("gate-capture", tmp_path / "capture.har")
        assert exported["entry_count"] >= 1
    finally:
        backend.stop("gate-capture")
        origin.shutdown()
        origin.server_close()


@pytest.mark.integration
def test_proxy_replays_a_captured_flow_back_to_the_origin() -> None:
    """Replay must re-issue a recorded request, not just report success.

    proxy.replay drives mitmproxy's ``replay.client`` command, whose name and
    flow-copy shape are exactly what a mitmproxy major bump moves -- the v12
    bump already broke this backend's shutdown path. The method returns
    ``replayed: True`` as soon as the command is scheduled, so only a counting
    origin can tell a real re-request from a no-op. Capture one GET, replay it,
    and assert the origin is hit a second time.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")

    origin = socketserver.TCPServer(("127.0.0.1", 0), _OriginHandler)
    origin_port = int(origin.server_address[1])
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = ProxyBackend()
    port = _free_port()
    backend.start("gate-replay", host="127.0.0.1", port=port)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
        )
        with opener.open(f"http://127.0.0.1:{origin_port}/thing", timeout=10) as response:
            assert response.read() == _OriginHandler.BODY

        deadline = time.monotonic() + 5.0
        listing = backend.flows("gate-replay", limit=10)
        while listing["count"] == 0 and time.monotonic() < deadline:
            time.sleep(0.1)
            listing = backend.flows("gate-replay", limit=10)
        assert listing["count"] >= 1, "no flow was recorded to replay"

        with _OriginHandler.hits_lock:
            hits_before = _OriginHandler.hits

        replayed = backend.replay("gate-replay", str(listing["flows"][0]["id"]))
        assert replayed["replayed"] is True

        # replay.client runs on the proxy loop and returns before the re-request
        # lands, so poll the origin's own counter rather than assuming it is done.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with _OriginHandler.hits_lock:
                if _OriginHandler.hits > hits_before:
                    break
            time.sleep(0.1)
        with _OriginHandler.hits_lock:
            assert _OriginHandler.hits > hits_before, "replay did not reach the origin"
    finally:
        backend.stop("gate-replay")
        origin.shutdown()
        origin.server_close()


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
