"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import http.server
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
def test_concurrent_starts_do_not_cross_the_mitmproxy_global_ctx() -> None:
    """Several proxies starting at once must all come up cleanly.

    mitmproxy keeps its addon context in process-global module attributes, so a
    second master under construction repoints the global that a first master's
    startup ``running`` hook reads; the resulting AttributeError is logged and
    then escalated by mitmproxy's errorcheck into a fatal "mitmproxy failed to
    start". Before the startup lock this failed a large fraction of overlapping
    starts (~9 of 24 in a 4-wide barrier stress); now every concurrent start
    must succeed. A barrier maximises the overlap the lock has to absorb.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    rounds, width = 5, 4
    failures: list[str] = []
    try:
        for rnd in range(rounds):
            ports = [_free_port() for _ in range(width)]
            barrier = threading.Barrier(width)
            errors: dict[str, str] = {}
            errors_lock = threading.Lock()

            def worker(
                index: int,
                port: int,
                rnd: int = rnd,
                barrier: threading.Barrier = barrier,
                errors: dict[str, str] = errors,
                errors_lock: threading.Lock = errors_lock,  # noqa: F821
            ) -> None:
                session = f"round{rnd}-{index}"
                try:
                    barrier.wait(timeout=10.0)
                    backend.start(session, host="127.0.0.1", port=port)
                except Exception as exc:  # noqa: BLE001 - record any start failure
                    with errors_lock:
                        errors[session] = f"{type(exc).__name__}: {exc}"

            threads = [
                threading.Thread(target=worker, args=(i, ports[i])) for i in range(width)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30.0)
            failures.extend(f"{name}: {reason}" for name, reason in errors.items())
            backend.close_all()
    finally:
        backend.close_all()
    assert not failures, "concurrent proxy starts failed:\n" + "\n".join(failures)


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    _BODY = b"mitm-capture-ok"

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self._BODY)))
        self.end_headers()
        self.wfile.write(self._BODY)

    def do_POST(self) -> None:  # noqa: N802 - http.server API name
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)  # drain the request body so the exchange closes
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self._BODY)))
        self.end_headers()
        self.wfile.write(self._BODY)

    def log_message(self, *args: object) -> None:  # keep the gate output quiet
        del args


@pytest.mark.integration
def test_proxy_captures_a_real_request_and_reads_it_back(tmp_path: Path) -> None:
    """The lifecycle gate proves the port binds; this proves capture works.

    Starting means listening is necessary but not sufficient: an unattended
    session depends on mitmproxy actually invoking the recorder addon on each
    response and on flows/flow_get/export_har reading that capture back. The
    mitmproxy addon and flow API drift across versions (the client says so), so
    this drives a real HTTP request through the proxy to a throwaway local
    origin and asserts the flow is recorded and retrievable on the installed
    mitmproxy -- plain HTTP, no TLS/CA trust needed. skip != pass when mitmproxy
    is absent.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    origin = http.server.HTTPServer(("127.0.0.1", 0), _OriginHandler)
    origin_port = int(origin.server_port)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    session = "capture-session"
    backend.start(session, host="127.0.0.1", port=proxy_port)
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
        )
        target = f"http://127.0.0.1:{origin_port}/probe"
        with opener.open(target, timeout=10) as response:
            assert response.read() == _OriginHandler._BODY

        # The addon records on the response event, which fires after the proxied
        # request completes; poll until the flow lands rather than racing it.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if backend.status(session)["flow_count"] >= 1:
                break
            time.sleep(0.1)
        else:
            pytest.fail("proxy forwarded the request but captured no flow")

        listing = backend.flows(session)
        assert listing["total"] >= 1
        match = next((f for f in listing["flows"] if "/probe" in f.get("url", "")), None)
        assert match is not None, listing["flows"]
        assert match["method"] == "GET"
        assert match["status"] == 200
        assert match["host"] == "127.0.0.1"

        detail = backend.flow_get(session, match["id"], tmp_path)
        assert detail["request"]["method"] == "GET"
        assert "/probe" in detail["request"]["url"]
        assert detail["response"]["status"] == 200
        assert detail["response"].get("body") == _OriginHandler._BODY.decode()

        # A POST exercises request-body capture, which the GET above cannot: send
        # a JSON payload through the proxy and assert flow_get reads it back from
        # the real mitmproxy flow's request.raw_content.
        payload_sent = b'{"probe":"body"}'
        post_req = urllib.request.Request(
            target, data=payload_sent, headers={"Content-Type": "application/json"}
        )
        with opener.open(post_req, timeout=10) as response:
            assert response.read() == _OriginHandler._BODY
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if backend.status(session)["flow_count"] >= 2:
                break
            time.sleep(0.1)
        else:
            pytest.fail("proxy forwarded the POST but captured no second flow")
        post_flow = next(
            (f for f in backend.flows(session)["flows"] if f.get("method") == "POST"), None
        )
        assert post_flow is not None, backend.flows(session)["flows"]
        post_detail = backend.flow_get(session, post_flow["id"], tmp_path)
        assert post_detail["request"]["method"] == "POST"
        assert post_detail["request"]["size"] == len(payload_sent)
        assert post_detail["request"].get("body") == payload_sent.decode()

        har = backend.export_har(session, tmp_path / "capture.har")
        assert har["entry_count"] >= 1
    finally:
        backend.stop(session)
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
