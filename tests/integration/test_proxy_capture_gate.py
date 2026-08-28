"""Live mitmproxy capture gate: real traffic in, retrievable flow out.

``test_proxy_lifecycle_gate.py`` proves the port contract (start listens, stop
frees the port, a busy port is refused) but never sends a single request
through the proxy, so the proxy's actual purpose -- intercepting HTTP and
recording a retrievable flow -- had no end-to-end coverage. This gate stands up
a throwaway localhost origin, routes a request through the proxy to it, and
asserts the flow was recorded and can be read back: the summary list, the full
request/response (including the POSTed body), and the HAR export. Everything is
plain HTTP against 127.0.0.1, so it needs no CA trust and no external network.

mitmproxy is optional; absent it the gate skips with a reason. The hosted
``linux-integration`` CI job installs the proxy extra, so this runs for real on
every push.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_GET_BODY = b"gate-origin-body-OK"
_POST_RESPONSE = b"posted-ok"


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
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_GET_BODY)))
        self.end_headers()
        self.wfile.write(_GET_BODY)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(201)
        self.send_header("Content-Length", str(len(_POST_RESPONSE)))
        self.end_headers()
        self.wfile.write(_POST_RESPONSE)

    def log_message(self, *_args: object) -> None:  # silence the stderr access log
        return


@contextmanager
def _origin_server() -> Iterator[int]:
    server = HTTPServer(("127.0.0.1", _free_port()), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@contextmanager
def _running_proxy(session: str) -> Iterator[tuple[ProxyBackend, int]]:
    backend = ProxyBackend()
    port = _free_port()
    backend.start(session, host="127.0.0.1", port=port)
    try:
        yield backend, port
    finally:
        backend.stop(session)


def _through_proxy(proxy_port: int) -> urllib.request.OpenerDirector:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    return urllib.request.build_opener(handler)


def _wait_for_flow(backend: ProxyBackend, session: str, *, minimum: int = 1) -> None:
    """The recorder fires on the proxy loop thread, so poll briefly for the flow."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if backend.status(session)["flow_count"] >= minimum:
            return
        time.sleep(0.05)
    pytest.fail(f"proxy did not record a flow within the deadline (session={session})")


@pytest.mark.integration
def test_proxy_records_a_request_routed_through_it(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    with _origin_server() as origin_port, _running_proxy("capture-get") as (backend, proxy_port):
        url = f"http://127.0.0.1:{origin_port}/probe?x=1"
        response = _through_proxy(proxy_port).open(url, timeout=10.0)
        assert response.status == 200
        assert response.read() == _GET_BODY

        _wait_for_flow(backend, "capture-get")

        flows = backend.flows("capture-get")
        assert flows["total"] == 1
        summary = flows["flows"][0]
        assert summary["method"] == "GET"
        assert summary["url"] == url
        assert summary["host"] == "127.0.0.1"
        assert summary["status"] == 200
        assert summary["response_size"] == len(_GET_BODY)

        # The whole point of capture: read the intercepted exchange back.
        detail = backend.flow_get("capture-get", summary["id"], tmp_path / "artifacts")
        assert detail["request"]["method"] == "GET"
        assert detail["request"]["url"] == url
        assert detail["response"]["status"] == 200
        assert detail["response"]["body"] == _GET_BODY.decode()


@pytest.mark.integration
def test_proxy_captures_the_request_body_and_exports_har(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")
    payload = b"secret-payload-42"
    with _origin_server() as origin_port, _running_proxy("capture-post") as (backend, proxy_port):
        url = f"http://127.0.0.1:{origin_port}/api"
        request = urllib.request.Request(url, data=payload, method="POST")
        response = _through_proxy(proxy_port).open(request, timeout=10.0)
        assert response.status == 201

        _wait_for_flow(backend, "capture-post")

        summary = backend.flows("capture-post")["flows"][0]
        assert summary["method"] == "POST"

        # A request body is what an agent reverse-engineering an API most wants:
        # what was actually POSTed must survive interception intact.
        detail = backend.flow_get("capture-post", summary["id"], tmp_path / "artifacts")
        assert detail["request"]["body"] == payload.decode()
        assert detail["response"]["status"] == 201

        har = backend.export_har("capture-post", tmp_path / "capture.har")
        assert har["entry_count"] == 1
        assert Path(har["path"]).is_file()
