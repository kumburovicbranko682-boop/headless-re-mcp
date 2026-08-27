"""Live mitmproxy capture gate: real traffic in, real flows back out.

The lifecycle gate (``test_proxy_lifecycle_gate.py``) proves the process
contract -- start binds, stop frees the port, an occupied port is refused. What
it never does is send a single byte through the proxy, so the whole reason the
proxy exists -- intercepting an exchange and handing the request/response back
to an agent -- had no test that drove real traffic and read it back. Every
``proxy.flows`` / ``proxy.flow.get`` / ``proxy.export_har`` / ``proxy.replay``
assertion here is against a genuine HTTP round trip captured by an in-process
mitmproxy 12.x, so a regression that silently records nothing (or drops the
request body, or exports an empty HAR) fails the gate instead of passing it.

The upstream is a throwaway localhost ``http.server`` and traffic is plain HTTP
routed through the proxy with an explicit ``ProxyHandler`` -- no TLS, no CA
install, nothing device-bound -- so this runs anywhere mitmproxy imports. When
mitmproxy is absent the capture test skips with an explicit "skip != pass"
message; the two guard tests (closed session, unconfigured backend) need no
proxy and always run.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.core.service import AnalysisService

_GET_MARKER = "upstream-get-body-marker"
_POST_MARKER = "client-post-body-marker"


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


class _UpstreamHandler(BaseHTTPRequestHandler):
    """A tiny origin server: GET returns a known body, POST echoes its body."""

    def log_message(self, *args: object) -> None:  # silence the default stderr spam
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send_json(200, {"marker": _GET_MARKER, "path": self.path})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        received = self.rfile.read(length).decode("utf-8", "replace")
        self._send_json(201, {"echo": received})


@pytest.fixture
def _upstream() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", _free_port()), _UpstreamHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5.0)


def _through_proxy(proxy_endpoint: str) -> urllib.request.OpenerDirector:
    # An explicit ProxyHandler always routes through the proxy -- unlike proxies
    # taken from the environment, it never consults no_proxy/localhost bypass, so
    # even a 127.0.0.1 upstream is forced through mitmproxy.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://{proxy_endpoint}"})
    )


def _poll_flow_total(service: AnalysisService, session_id: str, want: int) -> dict:
    deadline = time.monotonic() + 10.0
    data: dict = {}
    while time.monotonic() < deadline:
        result = service.proxy_flows(session_id)
        assert result.ok, result.error
        data = result.data
        if int(data["total"]) >= want:
            return data
        time.sleep(0.05)
    return data


@pytest.mark.integration
def test_proxy_captures_a_real_exchange_end_to_end(_upstream: str) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(_upstream, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        port = _free_port()
        started = service.proxy_start(session_id, host="127.0.0.1", port=port)
        assert started.ok, started.error
        assert started.data["running"] is True
        assert started.data["port"] == port
        assert started.data["endpoint"] == f"127.0.0.1:{port}"

        status = service.proxy_status(session_id)
        assert status.ok, status.error
        assert status.data["running"] is True
        assert status.data["flow_count"] == 0
        assert status.data["retained_max"] > 0

        # Drive one GET and one POST through the proxy at the local origin.
        opener = _through_proxy(started.data["endpoint"])
        got = opener.open(f"{_upstream}/hello", timeout=10)
        assert got.status == 200
        posted = opener.open(
            urllib.request.Request(
                f"{_upstream}/submit",
                data=_POST_MARKER.encode("utf-8"),
                method="POST",
            ),
            timeout=10,
        )
        assert posted.status == 201

        # Capture is recorded from mitmproxy's own loop thread, so poll.
        flows_data = _poll_flow_total(service, session_id, want=2)
        assert flows_data["total"] == 2, flows_data
        assert flows_data["count"] == 2
        flows = flows_data["flows"]

        get_summary = next(f for f in flows if f["method"] == "GET")
        post_summary = next(f for f in flows if f["method"] == "POST")
        assert get_summary["url"].endswith("/hello")
        assert get_summary["status"] == 200
        assert get_summary["host"] == "127.0.0.1"
        assert get_summary["response_size"] > 0
        assert post_summary["url"].endswith("/submit")
        assert post_summary["status"] == 201

        # flow.get must hand back the *recovered* bytes, not just metadata: the
        # server's real response body, and the client's real request body.
        get_detail = service.proxy_flow_get(session_id, get_summary["id"])
        assert get_detail.ok, get_detail.error
        assert get_detail.data["response"]["status"] == 200
        assert _GET_MARKER in get_detail.data["response"]["body"]
        resp_headers = get_detail.data["response"]["headers"]
        assert any(k.lower() == "content-type" for k in resp_headers), resp_headers

        post_detail = service.proxy_flow_get(session_id, post_summary["id"])
        assert post_detail.ok, post_detail.error
        # The request body -- "what was actually POSTed" -- is the whole point of
        # inspecting a captured API call, and is the field most easily lost.
        assert post_detail.data["request"]["body"] == _POST_MARKER

        # HAR export writes a real, parseable artifact with one entry per flow.
        har = service.proxy_export_har(session_id)
        assert har.ok, har.error
        assert har.data["entry_count"] == flows_data["total"]
        har_doc = json.loads(Path(har.data["path"]).read_text(encoding="utf-8"))
        assert len(har_doc["log"]["entries"]) == flows_data["total"]

        # Replay re-fires the captured request at the live origin, which the
        # proxy captures in turn, so the flow total must grow.
        replay = service.proxy_replay(session_id, get_summary["id"])
        assert replay.ok, replay.error
        assert replay.data["replayed"] is True
        after = _poll_flow_total(service, session_id, want=3)
        assert after["total"] >= 3, after

        # An unknown flow id is a clean not_found, never a crash.
        missing = service.proxy_flow_get(session_id, "not-a-real-flow-id")
        assert not missing.ok
        assert missing.error is not None
        assert missing.error.code == "not_found"

        stopped = service.proxy_stop(session_id)
        assert stopped.ok, stopped.error
        assert stopped.data["stopped"] is True
        assert service.proxy_status(session_id).data == {"running": False}
    finally:
        service.close_all()


@pytest.mark.integration
def test_proxy_start_refuses_a_closed_session() -> None:
    """State is checked before the backend, so this runs without mitmproxy."""
    service = AnalysisService()
    try:
        created = service.create_session("http://127.0.0.1:9", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        service.close_session(session_id)

        result = service.proxy_start(session_id, host="127.0.0.1", port=_free_port())
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


@pytest.mark.integration
def test_proxy_start_degrades_when_mitmproxy_is_unavailable() -> None:
    """A machine without mitmproxy gets capability_unavailable, not a stack trace."""
    service = AnalysisService()
    try:
        created = service.create_session("http://127.0.0.1:9", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        # Force the "not installed" verdict even on a box that has it, so this
        # guard is exercised on every run rather than only on a bare machine.
        service._proxy_backend._available = False

        result = service.proxy_start(session_id, host="127.0.0.1", port=_free_port())
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()
