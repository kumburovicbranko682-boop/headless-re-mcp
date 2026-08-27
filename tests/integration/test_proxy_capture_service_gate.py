"""Web dynamic gate: the proxy.* capture surface end to end through the service.

The proxy capture gate proves the ProxyBackend records real traffic, but it
drives the backend directly. The service layer wrapping it (ProxyAnalysisMixin)
is exercised for start/status only (the web lifecycle gate) and otherwise by
unit tests with a patched backend. So the service capture path is unproven end
to end -- and it does real work the backend gate cannot see:

- proxy.flow_get spills a large body to the session artifact area and registers
  it as a session artifact (_register_capture, kind proxy_flow_body), so an
  agent can read it back and retention can reclaim it,
- proxy.export_har writes into the session-keyed proxy/<session> dir and
  registers the HAR (kind proxy_har),
- proxy.start / export_har / stop land on the session timeline,
- the ok/data/meta envelope carries backend "proxy" and pagination fields,
- proxy.replay re-runs a captured flow through the service,
- a stopped capture answers proxy.flows with a structured invalid_state, never
  a crash.

Browser-free: a raw socket speaks absolute-form HTTP to the forward proxy, so
the request is guaranteed to traverse mitmproxy without a Chromium dependency.
Skips honestly when mitmproxy is missing. skip != pass.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# >200 KiB so proxy.flow_get spills the body to a file and registers it, while
# staying under the 2 MiB per-flow retain cap so the flow is kept (and replayable).
_BODY = b"PROXY-SVC-GATE-" + b"Z" * 300_000
_BLANK = "data:text/html,<html><head><title>proxy-svc</title></head><body>x</body></html>"


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


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _http_get_via_proxy(
    proxy_port: int, url: str, host_header: str, timeout: float = 10.0
) -> bytes:
    """Absolute-form HTTP to the forward proxy, so it traverses mitmproxy."""
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(
            (f"GET {url} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n").encode(
                "ascii"
            )
        )
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


@pytest.mark.integration
def test_proxy_capture_service_surface_end_to_end(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture service Gate not run (skip != pass)")

    origin_port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    proxy_port = _free_port()
    session_tree = settings.artifact_root.expanduser().resolve() / "proxy"
    try:
        created = service.create_session(_BLANK, target="web")
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])

        started = service.proxy_start(session_id, port=proxy_port)
        assert started.ok and started.data is not None, started.error
        assert started.meta.get("backend") == "proxy"
        assert started.data["running"] is True

        origin_url = f"http://127.0.0.1:{origin_port}/big"
        raw = _http_get_via_proxy(proxy_port, origin_url, f"127.0.0.1:{origin_port}")
        assert b"200" in raw.split(b"\r\n", 1)[0], raw[:200]

        # The recorder addon fires on the finished response; give it a moment.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            status = service.proxy_status(session_id)
            if status.ok and status.data and status.data.get("flow_count", 0) >= 1:
                break
            time.sleep(0.05)

        # proxy.flows: the flow is listed through the envelope with the
        # pagination companions and the backend label.
        flows = service.proxy_flows(session_id)
        assert flows.ok and flows.data is not None, flows.error
        assert flows.meta.get("backend") == "proxy"
        assert flows.data["total"] >= 1
        assert {"offset", "has_more", "dropped"} <= set(flows.data)
        flow = flows.data["flows"][0]
        assert flow["method"] == "GET" and flow["status"] == 200, flow
        flow_id = str(flow["id"])

        # proxy.flow_get spills the large body and registers it as an artifact.
        detail = service.proxy_flow_get(session_id, flow_id)
        assert detail.ok and detail.data is not None, detail.error
        body_path = detail.data["response"].get("body_path")
        assert isinstance(body_path, str) and body_path, detail.data
        spilled = Path(body_path).resolve()
        assert session_tree in spilled.parents, (spilled, session_tree)
        assert spilled.read_bytes() == _BODY
        artifact_id = detail.data.get("artifact_id")
        assert isinstance(artifact_id, str) and artifact_id, detail.data

        # The registered body is discoverable through the artifact surface.
        described = service.artifacts_describe(artifact_id)
        assert described.ok and described.data is not None, described.error
        assert described.data["artifact"]["kind"] == "proxy_flow_body"
        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None, listed.error
        kinds = {a["kind"] for a in listed.data["artifacts"]}
        assert "proxy_flow_body" in kinds, listed.data

        # proxy.replay re-runs the captured flow through the service.
        replayed = service.proxy_replay(session_id, flow_id)
        assert replayed.ok and replayed.data is not None, replayed.error
        assert replayed.data["replayed"] is True

        # proxy.export_har writes into proxy/<session> and registers the HAR.
        har = service.proxy_export_har(session_id)
        assert har.ok and har.data is not None, har.error
        assert har.data["entry_count"] >= 1
        har_path = Path(str(har.data["path"])).resolve()
        assert session_tree in har_path.parents, (har_path, session_tree)
        assert isinstance(har.data.get("artifact_id"), str) and har.data["artifact_id"]
        listed_after = service.artifacts_list(session_id)
        assert listed_after.ok and listed_after.data is not None, listed_after.error
        assert "proxy_har" in {a["kind"] for a in listed_after.data["artifacts"]}

        # The service records start / export / (below) stop on the timeline.
        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None, timeline.error
        events = {e.get("event") for e in timeline.data["events"]}
        assert {"proxy.start", "proxy.export_har"} <= events, events

        # proxy.stop tears the capture down; a later flows call is a structured
        # invalid_state, never a crash.
        stopped = service.proxy_stop(session_id)
        assert stopped.ok and stopped.data is not None, stopped.error
        assert stopped.data["stopped"] is True
        after = service.proxy_flows(session_id)
        assert after.ok is False and after.error is not None
        assert after.error.code == "invalid_state", after.error
    finally:
        service.close_all()
        origin.shutdown()
        origin.server_close()
