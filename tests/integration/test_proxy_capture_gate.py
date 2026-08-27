"""Live mitmproxy capture gate: a real request is recorded and decoded.

``test_proxy_lifecycle_gate`` proves start/stop/port behaviour but explicitly
asserts ``flow_count == 0`` -- it never routes a request through the proxy, so
the whole capture+decode surface is untested live: ``flows`` (the recorder addon
firing on a real response) and ``flow_get`` (decoding mitmproxy's request/response
-- ``req.method`` / ``req.pretty_url`` / ``req.headers`` / ``resp.status_code`` /
``resp.raw_content``). Those are version-sensitive mitmproxy APIs; a drift there
(the same class as the mitmproxy-12 ``Master.done`` change) would pass every
fake-based test and only fail at runtime against real traffic.

This gate stands up a throwaway local HTTP origin, starts the proxy, sends one
GET through it as an explicit HTTP proxy, then pins that the flow was captured and
decodes to the real method / URL / status / body / header -- and that export_har
emits a matching entry. Skips (skip != pass) when mitmproxy is not installed.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_MARKER = b"proxy-capture-marker-7731"


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


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Gate-Marker", "yes")
        self.end_headers()
        self.wfile.write(_MARKER)

    def log_message(self, *_args: object) -> None:
        pass  # keep the test output quiet


@pytest.mark.integration
def test_proxy_captures_and_decodes_a_real_flow(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    origin_port = origin.server_address[1]
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    session = "capture-session"
    backend.start(session, host="127.0.0.1", port=proxy_port)
    try:
        url = f"http://127.0.0.1:{origin_port}/probe?x=1"
        proxy_handler = urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{proxy_port}"}
        )
        opener = urllib.request.build_opener(proxy_handler)
        with opener.open(url, timeout=15) as response:
            assert response.status == 200
            assert response.read() == _MARKER

        # The recorder addon fires from mitmproxy's event loop; give it a moment.
        deadline = time.monotonic() + 10.0
        listed = backend.flows(session)
        while time.monotonic() < deadline and listed["total"] == 0:
            time.sleep(0.1)
            listed = backend.flows(session)
        assert listed["total"] >= 1, "the request was not captured as a flow"

        summary = next(
            (f for f in listed["flows"] if str(f.get("url", "")).endswith("/probe?x=1")),
            None,
        )
        assert summary is not None, f"captured flows did not include our request: {listed['flows']}"
        assert summary["method"] == "GET"
        assert summary["status"] == 200

        # flow_get must decode the full request/response off the mitmproxy flow.
        detail = backend.flow_get(session, summary["id"], tmp_path)
        assert detail["request"]["method"] == "GET"
        assert detail["request"]["url"].endswith("/probe?x=1")
        assert detail["response"]["status"] == 200
        assert detail["response"]["size"] == len(_MARKER)
        # Small body is inlined (not spilled to a file) and carries the marker.
        assert detail["response"]["body"] == _MARKER.decode()
        # A header we set on the origin response survives the decode.
        resp_headers = {k.lower(): v for k, v in detail["response"]["headers"].items()}
        assert resp_headers.get("x-gate-marker") == "yes"

        # export_har must render a matching entry from the same capture.
        har_path = tmp_path / "capture.har"
        har = backend.export_har(session, har_path)
        assert har["entry_count"] >= 1
        assert har_path.is_file()
        har_text = har_path.read_text(encoding="utf-8")
        assert "/probe?x=1" in har_text
    finally:
        backend.stop(session)
        origin.shutdown()
        origin.server_close()
