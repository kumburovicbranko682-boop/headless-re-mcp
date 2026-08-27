"""Live mitmproxy capture gate: real traffic in, a real flow back out.

The lifecycle gate proves the process contract -- start binds, stop frees the
port. This gate proves the thing the proxy backend actually exists for: a
request driven through it is recorded, can be read back with its body, exported
to HAR, and replayed to the origin. Without this, ``proxy.flows`` /
``proxy.flow.get`` / ``proxy.export_har`` / ``proxy.replay`` were asserted only
by unit tests against a hand-built recorder, never against a request that truly
crossed the wire. Uses only the stdlib as the client, so it runs wherever
mitmproxy is installed rather than needing the ``web`` extra (httpx) as well.
skip != pass: it skips only when mitmproxy is genuinely absent.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingTCPServer
from typing import Any

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_ORIGIN_BODY = b"gate-origin-body-7f3c"
_CAPTURE_WAIT_S = 5.0


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _OriginServer:
    """A throwaway HTTP origin that counts hits, so replay is observable."""

    def __init__(self) -> None:
        self.hits = 0
        port = _free_port()
        server = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
                server.hits += 1
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
                self.end_headers()
                self.wfile.write(_ORIGIN_BODY)

            def log_message(self, *args: object) -> None:
                pass  # keep the gate output clean

        self._httpd = ThreadingTCPServer(("127.0.0.1", port), _Handler)
        self._httpd.daemon_threads = True
        self.port = port
        self.url = f"http://127.0.0.1:{port}/resource"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def _get_through_proxy(target: str, proxy_port: int) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(target, timeout=10) as response:
        return int(response.status), response.read()


def _wait_for_flow(backend: ProxyBackend, session_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + _CAPTURE_WAIT_S
    while time.monotonic() < deadline:
        flows: list[dict[str, Any]] = backend.flows(session_id)["flows"]
        if flows:
            return flows[0]
        time.sleep(0.05)
    pytest.fail("proxy did not record the request that was driven through it")


@pytest.fixture
def origin() -> Iterator[_OriginServer]:
    server = _OriginServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def proxy_session() -> Iterator[tuple[ProxyBackend, str, int]]:
    # Skip here, before start(): a missing mitmproxy would otherwise raise in
    # fixture setup and read as an error rather than the honest skip it is.
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    session_id = "capture-gate"
    port = _free_port()
    backend.start(session_id, host="127.0.0.1", port=port)
    try:
        yield backend, session_id, port
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_captures_a_request_and_serves_the_flow_back(
    origin: _OriginServer,
    proxy_session: tuple[ProxyBackend, str, int],
    tmp_path: Path,
) -> None:
    backend, session_id, proxy_port = proxy_session

    status, body = _get_through_proxy(origin.url, proxy_port)
    assert status == 200
    assert body == _ORIGIN_BODY

    summary = _wait_for_flow(backend, session_id)
    assert summary["method"] == "GET"
    assert summary["url"] == origin.url
    assert summary["status"] == 200
    assert backend.status(session_id)["flow_count"] >= 1

    # The recorded flow must carry the real response, not just a summary line.
    detail = backend.flow_get(session_id, summary["id"], tmp_path / "flows")
    assert detail["request"]["method"] == "GET"
    assert detail["request"]["url"] == origin.url
    assert detail["response"]["status"] == 200
    assert detail["response"]["body"] == _ORIGIN_BODY.decode()

    har_path = tmp_path / "capture.har"
    exported = backend.export_har(session_id, har_path)
    assert exported["entry_count"] >= 1
    assert har_path.is_file()
    assert origin.url in har_path.read_text(encoding="utf-8")


@pytest.mark.integration
def test_proxy_replays_a_captured_request_to_the_origin(
    origin: _OriginServer,
    proxy_session: tuple[ProxyBackend, str, int],
) -> None:
    backend, session_id, proxy_port = proxy_session

    status, _ = _get_through_proxy(origin.url, proxy_port)
    assert status == 200
    summary = _wait_for_flow(backend, session_id)

    hits_before = origin.hits
    result = backend.replay(session_id, summary["id"])
    assert result["replayed"] is True

    # replay re-sends the captured request, so the origin must be hit again --
    # that second hit is the proof replay did more than return a happy dict.
    deadline = time.monotonic() + _CAPTURE_WAIT_S
    while time.monotonic() < deadline:
        if origin.hits > hits_before:
            break
        time.sleep(0.05)
    else:
        pytest.fail("replay reported success but the origin was never hit again")
