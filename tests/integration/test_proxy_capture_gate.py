"""Live proxy capture gate: traffic routed through mitmproxy is really recorded.

The lifecycle gate proves the port opens and closes; this gate proves the point
of the proxy. A local origin server serves a known body, a client is pointed at
the proxy, and the capture is read back through the service the way an operator
would: list the flow, fetch its request/response, export a HAR, and replay it.
Nothing here needs the internet or TLS -- plain HTTP through the proxy is enough
to exercise the record/read/export/replay path end to end.
"""

from __future__ import annotations

import http.server
import socket
import socketserver
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from itertools import count

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.core.service import AnalysisService

_BODY = b"proxy-capture-gate-D00DFEED"
_SETTLE_S = 15.0


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


class _CountingOrigin(http.server.BaseHTTPRequestHandler):
    """Serves a fixed body and a per-request counter so replays are visible."""

    hits = count()

    def do_GET(self) -> None:  # noqa: N802 - http.server dispatch name
        seq = next(type(self).hits)
        body = _BODY + f"#{seq}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence the test log
        return


@contextmanager
def _origin_server() -> Iterator[str]:
    _CountingOrigin.hits = count()
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _CountingOrigin)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5.0)


def _get_through_proxy(proxy_port: int, url: str) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(url, timeout=10) as response:
        assert response.status == 200
        return bytes(response.read())


def _wait_for_flow_total(service: AnalysisService, session_id: str, at_least: int) -> dict:
    deadline = time.monotonic() + _SETTLE_S
    listed = service.proxy_flows(session_id)
    while time.monotonic() < deadline:
        listed = service.proxy_flows(session_id)
        assert listed.ok, listed.error
        if listed.data["total"] >= at_least:
            return listed.data
        time.sleep(0.05)
    pytest.fail(
        f"proxy recorded {listed.data['total']} flows, expected at least {at_least}"
    )


@pytest.mark.integration
def test_proxy_records_and_reads_back_real_traffic() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _origin_server() as origin:
            created = service.create_session(f"{origin}/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            port = _free_port()
            started = service.proxy_start(session_id, host="127.0.0.1", port=port)
            assert started.ok, started.error

            url = f"{origin}/hello?token=1"
            body = _get_through_proxy(port, url)
            assert body.startswith(_BODY), body

            listed = _wait_for_flow_total(service, session_id, 1)
            summary = listed["flows"][0]
            assert summary["method"] == "GET"
            assert summary["url"] == url
            assert summary["status"] == 200
            assert summary["content_type"].startswith("text/plain")

            # flow.get must return the actual bytes the origin sent, not a
            # summary: a proxy that lists a flow it cannot reproduce is a
            # capture that silently lost the payload.
            detail = service.proxy_flow_get(session_id, summary["id"])
            assert detail.ok, detail.error
            assert detail.data["request"]["method"] == "GET"
            assert detail.data["request"]["url"] == url
            assert detail.data["response"]["status"] == 200
            assert detail.data["response"]["body"].encode().startswith(_BODY)

            exported = service.proxy_export_har(session_id)
            assert exported.ok, exported.error
            assert exported.data["entry_count"] >= 1
    finally:
        service.close_all()


@pytest.mark.integration
def test_proxy_replay_reissues_a_captured_request() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _origin_server() as origin:
            created = service.create_session(f"{origin}/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            port = _free_port()
            assert service.proxy_start(session_id, host="127.0.0.1", port=port).ok

            _get_through_proxy(port, f"{origin}/replay-me")
            first = _wait_for_flow_total(service, session_id, 1)
            flow_id = first["flows"][0]["id"]

            replayed = service.proxy_replay(session_id, flow_id)
            assert replayed.ok, replayed.error
            assert replayed.data["replayed"] is True

            # A replay that reached the origin lands as a second recorded flow;
            # a no-op would leave the count at one.
            after = _wait_for_flow_total(service, session_id, 2)
            assert after["total"] >= 2
    finally:
        service.close_all()
