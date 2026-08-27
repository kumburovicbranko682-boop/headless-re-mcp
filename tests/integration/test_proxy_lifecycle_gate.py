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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

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


_ORIGIN_MARKER = "proxy-origin-marker-9449"


class _OriginHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = f"{_ORIGIN_MARKER}:{self.path}".encode()
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
