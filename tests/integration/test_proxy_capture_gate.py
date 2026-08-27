"""Live mitmproxy capture gate: a request through the proxy is really recorded.

The lifecycle gate proves the port opens and closes; this proves the point of a
proxy -- that traffic routed through it lands in the ring, is retrievable with
its method/status/body intact, and exports to HAR. The interception + recording
path (``_FlowRecorder`` on the proxy's own asyncio thread) had no live coverage,
so a break in the addon wiring would have looked exactly like an idle proxy.
Deterministic: a stdlib HTTP origin and a stdlib proxied client, no network and
no extra dependency. skip != pass when mitmproxy is absent.
"""

from __future__ import annotations

import http.server
import socket
import socketserver
import threading
import time
import urllib.request
from collections.abc import Iterator
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
