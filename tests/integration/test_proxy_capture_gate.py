"""Live mitmproxy capture gate: a request routed through the proxy is recorded.

The lifecycle gate proves start/stop/bind; this proves the proxy's actual job.
It stands up a localhost origin, routes a real GET and a real POST through the
running proxy, and asserts the flow recorder, ``flow_get`` and ``export_har``
report what crossed the wire -- most importantly the POST *request* body, the
"what did the app actually send" that an RE session is usually after and that
the recorder used to drop. Hermetic (no external network) and Linux-portable;
skips honestly when mitmproxy is absent (skip != pass).
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_GET_BODY = b"hello world from origin"
_POST_PAYLOAD = b'{"secret":"H3adl3ss"}'


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


class _Origin(BaseHTTPRequestHandler):
    """A tiny origin: GET returns a fixed body, POST echoes its request body."""

    def log_message(self, *args: object) -> None:  # silence the default stderr spam
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_GET_BODY)))
        self.end_headers()
        self.wfile.write(_GET_BODY)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _route_get_and_post(proxy_port: int, origin_port: int) -> None:
    """Send one GET and one POST to the origin *through* the proxy.

    Uses stdlib urllib with an explicit http proxy so the job needs no HTTP
    client dependency; plain HTTP means no CA trust dance, which keeps the gate
    about capture mechanics rather than TLS setup.
    """
    import urllib.request

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    with opener.open(f"http://127.0.0.1:{origin_port}/hello", timeout=15) as resp:
        assert resp.status == 200
        assert resp.read() == _GET_BODY
    request = urllib.request.Request(
        f"http://127.0.0.1:{origin_port}/api",
        data=_POST_PAYLOAD,
        headers={"Content-Type": "application/json"},
    )
    with opener.open(request, timeout=15) as resp:
        assert resp.status == 201
        assert resp.read() == _POST_PAYLOAD  # the echo origin round-tripped the body


@pytest.mark.integration
def test_proxy_records_a_routed_request_end_to_end(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    origin = ThreadingHTTPServer(("127.0.0.1", _free_port()), _Origin)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    origin_port = origin.server_address[1]

    backend = ProxyBackend()
    proxy_port = _free_port()
    started = backend.start("capture", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        _route_get_and_post(proxy_port, origin_port)

        # The recorder fires on the proxy's loop thread after the client already
        # has its response, so poll rather than assume the flows are visible the
        # instant the requests return.
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and backend.status("capture")["flow_count"] < 2:
            time.sleep(0.05)
        assert backend.status("capture")["flow_count"] == 2, "both routed flows must be recorded"

        listing = backend.flows("capture")
        assert listing["total"] == 2
        by_method = {f["method"]: f for f in listing["flows"]}
        assert set(by_method) == {"GET", "POST"}
        assert by_method["GET"]["status"] == 200
        assert by_method["POST"]["status"] == 201
        assert by_method["POST"]["url"].endswith("/api")

        # flow_get on the POST is the crux: the request body -- what the client
        # actually sent -- must come back, not just the response. A recorder that
        # captured the flow but dropped the request body would still list the flow
        # above and only fail here.
        got_post = backend.flow_get("capture", by_method["POST"]["id"], tmp_path)
        assert got_post["request"]["method"] == "POST"
        assert got_post["request"].get("body") == _POST_PAYLOAD.decode()
        assert got_post["response"]["status"] == 201
        assert got_post["response"].get("body") == _POST_PAYLOAD.decode()

        got_get = backend.flow_get("capture", by_method["GET"]["id"], tmp_path)
        assert got_get["response"]["status"] == 200
        assert got_get["response"].get("body") == _GET_BODY.decode()

        # export_har must serialize both captured flows to a real file.
        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture", har_path)
        assert exported["entry_count"] == 2
        assert har_path.is_file()
        assert har_path.stat().st_size > 0
        assert '"HAR' in har_path.read_text() or '"log"' in har_path.read_text()
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
