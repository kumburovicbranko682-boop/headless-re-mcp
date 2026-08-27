"""Live mitmproxy capture gate: traffic through the proxy is actually recorded.

The lifecycle gate proves start/stop/port release. This one proves the part an
operator actually wants -- that a request routed through the proxy shows up in
``flows``, that ``flow.get`` returns its request/response, and that
``export_har`` writes a HAR carrying it. It drives a real HTTP round trip
through the proxy against a throwaway local server, so it needs no network and
no CA (plain HTTP), and skips honestly when mitmproxy is absent (skip != pass).
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_MARKER = b"HEADLESS_RE_PROXY_CAPTURE_MARKER"
_PATH = "/probe/resource"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_MARKER)))
        self.end_headers()
        self.wfile.write(_MARKER)

    def log_message(self, *_args: object) -> None:
        """Silence the default stderr access log during the gate."""


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


@pytest.fixture()
def _origin() -> Iterator[str]:
    """A throwaway HTTP origin the proxy can forward to."""
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}{_PATH}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _get_through_proxy(url: str, proxy_port: int) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(url, timeout=10.0) as response:
        assert response.status == 200
        return bytes(response.read())


def _matching_flows(backend: ProxyBackend, session_id: str) -> list[dict]:
    return [
        flow
        for flow in backend.flows(session_id)["flows"]
        if _PATH in str(flow.get("url", ""))
    ]


def _wait_for_flow(backend: ProxyBackend, session_id: str, *, at_least: int = 1) -> list[dict]:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        matches = _matching_flows(backend, session_id)
        if len(matches) >= at_least:
            return matches
        time.sleep(0.1)
    raise AssertionError(
        f"proxy did not record {at_least} matching flow(s) within the timeout"
    )


@pytest.mark.integration
def test_a_request_through_the_proxy_is_captured(_origin: str, tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("capture", host="127.0.0.1", port=port)
    try:
        body = _get_through_proxy(_origin, port)
        assert body == _MARKER

        flow = _wait_for_flow(backend, "capture")[0]
        assert flow["method"] == "GET"
        assert flow["status"] == 200
        flow_id = str(flow["id"])

        detail = backend.flow_get("capture", flow_id, tmp_path)
        assert detail["request"]["method"] == "GET"
        assert _PATH in detail["request"]["url"]
        assert detail["response"]["status"] == 200
        # Small body: returned inline rather than spilled to a file.
        assert _MARKER.decode() in detail["response"]["body"]

        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture", har_path)
        assert exported["entry_count"] >= 1
        loaded = json.loads(har_path.read_text(encoding="utf-8"))
        urls = [entry["request"]["url"] for entry in loaded["log"]["entries"]]
        assert any(_PATH in url for url in urls)
    finally:
        backend.close_all()


@pytest.mark.integration
def test_replaying_a_flow_reissues_the_request(_origin: str, tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("replay", host="127.0.0.1", port=port)
    try:
        assert _get_through_proxy(_origin, port) == _MARKER
        first = _wait_for_flow(backend, "replay")[0]

        replayed = backend.replay("replay", str(first["id"]))
        assert replayed["replayed"] is True

        # Replay re-sends through the same proxy pipeline, so a second flow for
        # the same URL must show up -- proof the request really went out again.
        again = _wait_for_flow(backend, "replay", at_least=2)
        assert len(again) >= 2
        assert all(flow["status"] == 200 for flow in again)
    finally:
        backend.close_all()
