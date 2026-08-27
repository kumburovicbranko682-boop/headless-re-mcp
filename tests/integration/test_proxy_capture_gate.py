"""Live mitmproxy capture gate: record, retrieve, export, and replay a flow.

The lifecycle gate proves start/stop/port; it never sends a byte through the
proxy, so _FlowRecorder.response and the flows / flow_get / export_har / replay
read paths have only unit coverage against fake flow objects. This routes a real
HTTP request through the running proxy to a local server and checks the captured
flow round-trips -- the end-to-end contract an unattended capture depends on.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_BODY = b"gate-capture-body-payload"


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
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *args: object) -> None:  # keep the gate output quiet
        del args


def _start_origin() -> tuple[HTTPServer, int, threading.Thread]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, name="gate-origin", daemon=True)
    thread.start()
    return server, port, thread


def _get_through_proxy(proxy_port: int, url: str) -> bytes:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    opener = urllib.request.build_opener(handler)
    with opener.open(url, timeout=15) as response:
        return response.read()


def _wait_for_flows(backend: ProxyBackend, session: str, at_least: int) -> list[dict]:
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        listing = backend.flows(session)
        if listing["count"] >= at_least:
            return listing["flows"]
        time.sleep(0.1)
    return backend.flows(session)["flows"]


@pytest.mark.integration
def test_proxy_records_and_retrieves_a_real_http_flow(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    origin, origin_port, _ = _start_origin()
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("capture", host="127.0.0.1", port=proxy_port)
    try:
        url = f"http://127.0.0.1:{origin_port}/hello"
        assert _get_through_proxy(proxy_port, url) == _BODY

        flows = _wait_for_flows(backend, "capture", at_least=1)
        assert flows, "the proxy recorded no flow for a request that went through it"
        match = next((f for f in flows if str(f.get("url", "")).endswith("/hello")), None)
        assert match is not None, f"captured flows did not include the request: {flows}"
        assert match["method"] == "GET"
        assert match["status"] == 200

        detail = backend.flow_get("capture", match["id"], tmp_path)
        assert detail["request"]["url"].endswith("/hello")
        # A small body inlines rather than spilling, and must be the real bytes.
        assert "gate-capture-body-payload" in detail["response"]["body"]
        assert detail["response"]["status"] == 200

        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture", har_path)
        assert exported["entry_count"] >= 1
        har = json.loads(har_path.read_text(encoding="utf-8"))
        urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
        assert any(str(u).endswith("/hello") for u in urls)
    finally:
        backend.stop("capture")
        origin.shutdown()


@pytest.mark.integration
def test_proxy_replays_a_captured_flow(tmp_path: Path) -> None:
    del tmp_path
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    origin, origin_port, _ = _start_origin()
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("replay", host="127.0.0.1", port=proxy_port)
    try:
        url = f"http://127.0.0.1:{origin_port}/replay-me"
        assert _get_through_proxy(proxy_port, url) == _BODY
        flows = _wait_for_flows(backend, "replay", at_least=1)
        assert flows, "no flow to replay"
        flow_id = flows[0]["id"]

        result = backend.replay("replay", flow_id)
        assert result["replayed"] is True

        # replay.client copies the flow (new id) and sends it again, so a second
        # flow must land -- proving the replay actually hit the origin, not just
        # that the command returned.
        replayed = _wait_for_flows(backend, "replay", at_least=2)
        assert len(replayed) >= 2, f"replay did not produce a second flow: {replayed}"
    finally:
        backend.stop("replay")
        origin.shutdown()
