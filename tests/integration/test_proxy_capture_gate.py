"""Live mitmproxy capture gate: a real flow through the data path.

The lifecycle gate proves start/stop honesty but never passes one HTTP request
through the capture, so the whole data path -- the ``_FlowRecorder`` addon fed
by real mitmproxy flow objects, ``flows`` summaries, ``flow_get`` body
retrieval, ``export_har``, ``replay`` -- had no real-tool coverage at all. The
unit tests drive that path with hand-built fakes that encode the *assumed*
mitmproxy attribute shapes (``request.pretty_url``, ``response.raw_content``,
``flow.id``); if the real API drifts the fakes stay green while a live capture
records nothing, the same shape of gap that let the webcrack ``-f`` break ship
behind a passing deobfuscate gate. Everything here is loopback-only: a local
origin server, plain HTTP (no CA trust needed), no network egress.
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

_ORIGIN_BODY = b"hello-from-origin"
_WAIT_S = 15.0


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


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server contract
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
        self.end_headers()
        self.wfile.write(_ORIGIN_BODY)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        del args


@pytest.fixture()
def origin_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _get_via_proxy(proxy_port: int, url: str) -> bytes:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(url, timeout=10.0) as reply:
        return reply.read()


def _wait_for_flows(backend: ProxyBackend, session: str, minimum: int) -> list[dict]:
    """Recording happens on mitmproxy's loop after the client already has its
    reply, so the ring can lag the HTTP round-trip by a beat; poll with a
    deadline instead of asserting immediately."""
    deadline = time.monotonic() + _WAIT_S
    while time.monotonic() < deadline:
        listed = backend.flows(session)
        if listed["total"] >= minimum:
            return list(listed["flows"])
        time.sleep(0.1)
    pytest.fail(f"capture never reached {minimum} flow(s) within {_WAIT_S}s")


@pytest.mark.integration
def test_one_real_request_flows_through_summary_body_and_har(
    origin_server: str, tmp_path: Path
) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("capture-gate", host="127.0.0.1", port=proxy_port)
    try:
        url = f"{origin_server}/hello?probe=1"
        assert _get_via_proxy(proxy_port, url) == _ORIGIN_BODY

        flows = _wait_for_flows(backend, "capture-gate", 1)
        summary = flows[0]
        assert summary["method"] == "GET"
        assert summary["url"] == url
        assert summary["status"] == 200
        assert summary["response_size"] == len(_ORIGIN_BODY)
        assert not summary.get("error")

        detail = backend.flow_get("capture-gate", str(summary["id"]), tmp_path)
        assert detail["request"]["method"] == "GET"
        assert detail["request"]["url"] == url
        assert detail["response"]["status"] == 200
        # The retained body must be the origin's actual bytes, inline as text.
        assert detail["response"]["body"] == _ORIGIN_BODY.decode("ascii")
        assert detail["response"]["size"] == len(_ORIGIN_BODY)

        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture-gate", har_path)
        assert exported["entry_count"] == 1
        document = json.loads(har_path.read_text(encoding="utf-8"))
        entries = document["log"]["entries"]
        assert len(entries) == 1
        assert entries[0]["request"]["url"] == url
        assert entries[0]["response"]["status"] == 200
    finally:
        backend.close_all()


@pytest.mark.integration
def test_replay_reissues_the_request_and_records_a_second_flow(
    origin_server: str, tmp_path: Path
) -> None:
    """replay drives mitmproxy's own ``replay.client`` command against the real
    master; the unit fakes cannot tell whether that command name, its argument
    shape, or the loop hand-off still match the installed mitmproxy."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("replay-gate", host="127.0.0.1", port=proxy_port)
    try:
        url = f"{origin_server}/replay-me"
        assert _get_via_proxy(proxy_port, url) == _ORIGIN_BODY
        first = _wait_for_flows(backend, "replay-gate", 1)[0]

        replayed = backend.replay("replay-gate", str(first["id"]))
        assert replayed["replayed"] is True

        # The replayed request goes proxy->origin again and lands in the ring
        # as a flow of its own, for the same URL with a fresh 200.
        flows = _wait_for_flows(backend, "replay-gate", 2)
        assert [f["url"] for f in flows] == [url, url]
        assert all(f["status"] == 200 for f in flows)
    finally:
        backend.close_all()
