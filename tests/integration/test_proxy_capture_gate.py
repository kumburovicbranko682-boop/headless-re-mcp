"""Live mitmproxy capture + replay gate: the proxy really records and re-issues.

The lifecycle gate proves the port opens and closes; this proves the point of a
proxy -- that traffic routed through it lands in the ring, is retrievable with
its method/status/body intact, exports to HAR, and can be replayed back to the
origin. The interception/recording path (``_FlowRecorder`` on the proxy's own
asyncio thread) and ``replay.client`` had no live coverage, so a break in the
addon wiring or the replay dispatch would have looked exactly like an idle proxy
that still answered ``{"replayed": True}``. Deterministic: a stdlib HTTP origin
(the replay test's origin counts its hits) and a stdlib proxied client, no
network and no extra dependency. skip != pass when mitmproxy is absent.
"""

from __future__ import annotations

import http.server
import socket
import socketserver
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_BODY = b'{"hello": "proxy-capture"}'


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


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *_args: object) -> None:  # silence the test server
        return


@pytest.fixture
def origin() -> Iterator[str]:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/data.json"
    finally:
        httpd.shutdown()
        thread.join(timeout=5.0)


class _CountingServer(socketserver.ThreadingTCPServer):
    """An origin that counts how many times it was actually hit."""

    allow_reuse_address = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.hits = 0
        self.hits_lock = threading.Lock()


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        server: _CountingServer = self.server  # type: ignore[assignment]
        with server.hits_lock:
            server.hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def counting_origin() -> Iterator[_CountingServer]:
    httpd = _CountingServer(("127.0.0.1", 0), _CountingHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        thread.join(timeout=5.0)


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def _get_through_proxy(url: str, proxy_port: int) -> tuple[int, bytes]:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    opener = urllib.request.build_opener(handler)
    with opener.open(url, timeout=10.0) as resp:
        return int(resp.status), resp.read()


@pytest.mark.integration
def test_a_request_routed_through_the_proxy_is_recorded_and_retrievable(
    origin: str, tmp_path: Path
) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("capture-session", host="127.0.0.1", port=port)
    try:
        status, body = _get_through_proxy(origin, port)
        assert status == 200
        assert body == _BODY

        # Interception is handled on the proxy's own thread, so the flow may
        # land a beat after the client returns. Poll rather than sleep-guess.
        flows: list[dict[str, object]] = []
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            listed = backend.flows("capture-session")
            flows = list(listed["flows"])
            if flows:
                break
            time.sleep(0.1)
        assert flows, "no flow was recorded for a request that went through the proxy"

        recorded = flows[0]
        assert recorded.get("method") == "GET"
        assert str(recorded.get("url", "")).endswith("/data.json")
        assert recorded.get("status") == 200

        flow_id = str(recorded.get("id"))
        detail = backend.flow_get("capture-session", flow_id, tmp_path)
        assert detail["request"]["method"] == "GET"
        assert detail["response"]["status"] == 200
        # Small bodies come back inline rather than spilled to an artifact.
        assert detail["response"].get("body") == _BODY.decode("utf-8")

        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture-session", har_path)
        assert har_path.is_file()
        assert exported.get("entry_count", 0) >= 1
    finally:
        backend.stop("capture-session")


@pytest.mark.integration
def test_a_captured_flow_can_be_replayed_back_to_the_origin(
    counting_origin: _CountingServer,
) -> None:
    """proxy.replay must re-issue a recorded request, not just echo success.

    ``replay`` hands the flow to mitmproxy's ``replay.client`` on the proxy's own
    loop; nothing else exercises that path live, and a broken wiring would still
    return ``{"replayed": True}``. The origin counts its hits, so the proof is
    that the request actually arrives a second time -- and, because the replayed
    request goes back through the proxy, that it is recaptured as a new flow.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    url = f"http://127.0.0.1:{int(counting_origin.server_address[1])}/data.json"
    backend = ProxyBackend()
    port = _free_port()
    backend.start("replay-session", host="127.0.0.1", port=port)
    try:
        status, body = _get_through_proxy(url, port)
        assert status == 200
        assert body == _BODY
        assert _wait_until(lambda: counting_origin.hits >= 1), "origin never saw the first request"

        assert _wait_until(lambda: bool(backend.flows("replay-session")["flows"])), (
            "no flow was recorded to replay"
        )
        flow_id = str(backend.flows("replay-session")["flows"][0]["id"])

        replayed = backend.replay("replay-session", flow_id)
        assert replayed.get("replayed") is True

        # The request must actually reach the origin a second time...
        assert _wait_until(lambda: counting_origin.hits >= 2), "replay did not reach the origin"
        # ...and, having gone back through the proxy, be recaptured.
        assert _wait_until(lambda: len(backend.flows("replay-session")["flows"]) >= 2), (
            "the replayed request was not recaptured as a new flow"
        )
    finally:
        backend.stop("replay-session")
