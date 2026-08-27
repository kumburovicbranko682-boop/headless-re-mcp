"""Live mitmproxy capture gate: a request routed through the proxy is recorded.

The lifecycle gate proves the socket contract -- start binds, stop releases. It
never sends a byte through the proxy, so the capability the proxy exists for --
intercepting a real request and handing back what crossed the wire -- had no
live coverage at all: every assertion about flow capture, body retrieval, HAR
export and replay lived only in unit tests driven by fake flow objects.

This gate closes that gap end to end against a real origin server. It routes an
HTTP GET and POST through a running proxy and proves the recorder saw both, that
``flow.get`` returns the response body an agent came for and the request body it
actually POSTed, that the HAR export names every captured flow, that a captured
flow can be replayed, and that a request to a dead upstream is still recorded --
marked as an error with a null status -- rather than silently dropped.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_MARKER = b'{"secret":"H3adl3ss_proxy_capture","n":42}'
_POST_BODY = b"who=agent&what=reverse-engineering"


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    """A tiny deterministic origin: JSON on GET, echo-ish 201 on POST."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib dispatch name
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_MARKER)))
        self.end_headers()
        self.wfile.write(_MARKER)

    def do_POST(self) -> None:  # noqa: N802 - stdlib dispatch name
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"created")

    def log_message(self, *_args: object) -> None:
        return


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


_SKIP = "mitmproxy not installed — proxy capture Gate not run (skip != pass)"


@pytest.fixture()
def origin() -> Iterator[str]:
    """A local HTTP origin the proxy can forward to, on its own thread."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, name="capture-origin", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _opener(proxy_port: int) -> urllib.request.OpenerDirector:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    return urllib.request.build_opener(handler)


def _wait_for_flows(backend: ProxyBackend, session: str, want: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if backend.flows(session)["total"] >= want:
            return
        time.sleep(0.05)
    raise AssertionError(f"expected >= {want} flows, saw {backend.flows(session)['total']}")


@pytest.mark.integration
def test_get_and_post_are_captured_with_retrievable_bodies(origin: str, tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip(_SKIP)
    backend = ProxyBackend()
    port = _free_port()
    backend.start("capture", host="127.0.0.1", port=port)
    try:
        opener = _opener(port)
        got = opener.open(f"{origin}/thing", timeout=10)
        assert got.status == 200
        assert got.read() == _MARKER
        posted = opener.open(
            urllib.request.Request(f"{origin}/submit", data=_POST_BODY, method="POST"),
            timeout=10,
        )
        assert posted.status == 201

        _wait_for_flows(backend, "capture", 2)
        flows = backend.flows("capture")["flows"]
        by_method = {f["method"]: f for f in flows}
        assert set(by_method) == {"GET", "POST"}

        get_flow = by_method["GET"]
        assert get_flow["status"] == 200
        assert get_flow["content_type"] == "application/json"
        assert get_flow["response_size"] == len(_MARKER)
        assert get_flow["url"].endswith("/thing")

        post_flow = by_method["POST"]
        assert post_flow["status"] == 201
        assert post_flow["url"].endswith("/submit")

        # The response body an agent came to read, decoded inline as text.
        get_detail = backend.flow_get("capture", get_flow["id"], tmp_path)
        assert get_detail["response"]["body"] == _MARKER.decode()
        assert get_detail["response"]["status"] == 200

        # The request body it actually POSTed, which the summary never carries.
        post_detail = backend.flow_get("capture", post_flow["id"], tmp_path)
        assert post_detail["request"]["body"] == _POST_BODY.decode()
        assert post_detail["request"]["method"] == "POST"
    finally:
        backend.close_all()


@pytest.mark.integration
def test_har_export_names_every_captured_flow(origin: str, tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip(_SKIP)
    backend = ProxyBackend()
    port = _free_port()
    backend.start("har", host="127.0.0.1", port=port)
    try:
        opener = _opener(port)
        opener.open(f"{origin}/a", timeout=10).read()
        opener.open(f"{origin}/b", timeout=10).read()
        _wait_for_flows(backend, "har", 2)

        out = tmp_path / "capture.har"
        result = backend.export_har("har", out)
        assert result["entry_count"] == 2
        assert result["truncated"] is False

        doc = json.loads(out.read_text(encoding="utf-8"))
        log = doc["log"]
        assert log["version"] == "1.2"
        assert len(log["entries"]) == 2
        urls = {entry["request"]["url"] for entry in log["entries"]}
        assert {f"{origin}/a", f"{origin}/b"} == urls
        for entry in log["entries"]:
            # HAR 1.2 requires these keys on every entry, even when unknown.
            assert entry["response"]["status"] == 200
            assert "content" in entry["response"]
            assert "timings" in entry
    finally:
        backend.close_all()


@pytest.mark.integration
def test_a_captured_flow_can_be_replayed(origin: str) -> None:
    if not _mitmproxy_available():
        pytest.skip(_SKIP)
    backend = ProxyBackend()
    port = _free_port()
    backend.start("replay", host="127.0.0.1", port=port)
    try:
        _opener(port).open(f"{origin}/once", timeout=10).read()
        _wait_for_flows(backend, "replay", 1)
        flow_id = backend.flows("replay")["flows"][0]["id"]

        result = backend.replay("replay", flow_id)
        assert result["replayed"] is True

        # Replay re-issues the request through the proxy, so the recorder sees
        # a second flow for the same URL rather than mutating the first.
        _wait_for_flows(backend, "replay", 2)
    finally:
        backend.close_all()


@pytest.mark.integration
def test_a_request_to_a_dead_upstream_is_captured_as_an_error(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip(_SKIP)
    dead_port = _free_port()  # reserved, nothing listening
    backend = ProxyBackend()
    port = _free_port()
    backend.start("error", host="127.0.0.1", port=port)
    try:
        opener = _opener(port)
        # The proxy answers the client with a synthesized 502; what matters is
        # what the recorder keeps, so the client-side error is expected.
        with pytest.raises(urllib.error.HTTPError) as info:
            opener.open(f"http://127.0.0.1:{dead_port}/gone", timeout=10)
        assert info.value.code == 502

        _wait_for_flows(backend, "error", 1)
        flow = backend.flows("error")["flows"][0]
        assert flow["error"] is True
        assert flow["error_msg"]
        # A completed flow always carries a numeric status; an errored one's is
        # null, which is how a reader tells "host refused" from "host answered".
        assert flow["status"] is None
        assert flow["response_size"] == 0

        # The failed request is still fully retrievable -- which host, which
        # path refused -- with a null-status, empty-body response rather than a
        # fabricated success.
        detail = backend.flow_get("error", flow["id"], tmp_path)
        assert detail["request"]["method"] == "GET"
        assert detail["request"]["url"].endswith("/gone")
        assert detail["response"]["status"] is None
        assert detail["response"]["body"] == ""
    finally:
        backend.close_all()
