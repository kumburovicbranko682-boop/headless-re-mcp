"""Live mitmproxy capture gate: a real HTTP flow is recorded, read back, replayed.

The lifecycle gate proves the process contract -- start binds, stop frees the
port, an occupied port is refused -- but it deliberately routes no traffic, so
``flow_count`` stays 0 and the thing the proxy exists to do (intercept a request
and let the RE tools read it back) was never exercised end to end. Every capture
assertion lived in unit tests against a hand-built fake flow, never a byte that
actually crossed the proxy.

This gate stands up a throwaway origin server, drives a real HTTP GET through the
running proxy, and then reads the capture back through the same API the proxy.*
tools use:

* ``flows``/``status``: the request was recorded with its real method, URL and
  status code.
* ``flow_get``: the recorded response carries the exact body the origin sent --
  proof the proxy saw the response, not merely the request line.
* ``export_har``: the capture serialises to a HAR entry.
* ``replay``: re-issuing a captured flow produces a second recorded flow.

Plain HTTP is used on purpose: it needs no CA trust, so the gate proves the
capture path itself rather than TLS provisioning. skip != pass: it skips only
when mitmproxy is genuinely absent, never silently.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_ORIGIN_BODY = b"HEADLESS-CAPTURE-OK"


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


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_ORIGIN_BODY)))
        self.end_headers()
        self.wfile.write(_ORIGIN_BODY)

    def log_message(self, *args: object) -> None:  # silence the stdlib access log
        return


@contextmanager
def _local_origin() -> Iterator[int]:
    """A throwaway HTTP origin on localhost, torn down on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, name="gate-origin", daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _get_through_proxy(proxy_port: int, url: str) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(url, timeout=15) as response:
        return int(response.status), response.read()


def _wait_for_flows(backend: ProxyBackend, session: str, at_least: int) -> int:
    """Poll until the recorder has ``at_least`` flows; the response hook is async.

    The recorder is written from mitmproxy's event-loop thread after the response
    completes, so a just-returned client read can briefly precede the record.
    """
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        count = int(backend.status(session)["flow_count"])
        if count >= at_least:
            return count
        time.sleep(0.05)
    return int(backend.status(session)["flow_count"])


@pytest.mark.integration
def test_proxy_captures_a_real_http_flow(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("capture", host="127.0.0.1", port=proxy_port)
    try:
        with _local_origin() as origin_port:
            url = f"http://127.0.0.1:{origin_port}/probe?x=1"
            status, body = _get_through_proxy(proxy_port, url)
            assert status == 200
            assert body == _ORIGIN_BODY

            assert _wait_for_flows(backend, "capture", 1) >= 1, "no flow was captured"

            listed = backend.flows("capture")
            assert listed["total"] >= 1
            flow = listed["flows"][0]
            assert flow["method"] == "GET"
            assert flow["url"] == url
            assert flow["status"] == 200

            # flow_get must return the exact bytes the origin sent, proving the
            # proxy observed the response body and not just the request line.
            detail = backend.flow_get("capture", flow["id"], tmp_path / "artifacts")
            assert detail["response"]["status"] == 200
            assert detail["response"]["body"] == _ORIGIN_BODY.decode()
            assert detail["request"]["method"] == "GET"

            exported = backend.export_har("capture", tmp_path / "capture.har")
            assert exported["entry_count"] >= 1
            assert Path(exported["path"]).is_file()
    finally:
        backend.stop("capture")


@pytest.mark.integration
def test_proxy_replays_a_captured_flow() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("replay", host="127.0.0.1", port=proxy_port)
    try:
        with _local_origin() as origin_port:
            status, _ = _get_through_proxy(proxy_port, f"http://127.0.0.1:{origin_port}/once")
            assert status == 200
            assert _wait_for_flows(backend, "replay", 1) >= 1

            flow_id = backend.flows("replay")["flows"][0]["id"]
            replayed = backend.replay("replay", flow_id)
            assert replayed["replayed"] is True

            # A replay re-issues the request through the proxy, so it must land
            # as a second recorded flow rather than vanishing.
            assert _wait_for_flows(backend, "replay", 2) >= 2, "replay produced no new flow"
    finally:
        backend.stop("replay")
