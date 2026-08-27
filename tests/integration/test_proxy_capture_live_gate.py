"""Proxy capture live gate: a real request routed through mitmproxy is recorded.

The proxy lifecycle gate proves the listener starts, stops and frees its port,
but it only ever asserts ``flow_count == 0`` -- capturing traffic, the entire
reason the proxy exists, had no live coverage. Nothing drove a request through
the proxy and then read it back, so ``flows``, ``flow_get``, ``export_har`` and
``replay`` only ever ran against mocks (and the request-body capture path, which
the code notes "used to be dropped entirely", was never exercised end to end).

The fixture is a throwaway localhost HTTP server, and the client request is sent
through the proxy over plain HTTP, so the capture runs for real with no external
network and no CA trust dance. The gate then reads the flow back through the same
backend the proxy.* tools use: the recorded GET, its response body, a POST's
request body, a HAR export, and a client-side replay.

Skip != pass: the gate skips with a reason only when mitmproxy is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_RESPONSE_MARKER = b'{"marker": "PROXY_FLOW_42"}'
_REQUEST_MARKER = b'{"sent": "CLIENT_BODY_99"}'


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass

    def _reply(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_RESPONSE_MARKER)))
        self.end_headers()
        self.wfile.write(_RESPONSE_MARKER)

    def do_GET(self) -> None:
        self._reply()

    def do_POST(self) -> None:
        # Drain the request body so the connection completes cleanly; the proxy
        # captures it regardless of what the origin does with it.
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._reply()


@contextmanager
def _origin_site() -> Iterator[str]:
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _through_proxy(proxy_port: int, url: str, *, data: bytes | None = None) -> bytes:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    with opener.open(request, timeout=15) as response:
        return bytes(response.read())


def _wait_for(predicate: Callable[[], bool], *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


@pytest.mark.integration
def test_proxy_captures_a_real_flow_end_to_end(tmp_path: Path) -> None:
    backend = ProxyBackend()
    try:
        backend._check_available()
    except ProxyError:
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    port = _free_port()
    with _origin_site() as origin:
        started = backend.start("capture", port=port)
        assert started["running"] is True
        try:
            got = _through_proxy(port, f"{origin}/api")
            assert got == _RESPONSE_MARKER, "the origin body must reach the client via the proxy"
            _through_proxy(port, f"{origin}/echo", data=_REQUEST_MARKER)

            # Capture is delivered on the response hook, slightly after the client
            # call returns, so wait for both flows rather than racing them.
            assert _wait_for(lambda: backend.flows("capture", limit=100)["count"] >= 2), (
                "the proxy never recorded the two requests routed through it"
            )
            flows = backend.flows("capture", limit=100)["flows"]
            get_flow = next(f for f in flows if str(f.get("url")).endswith("/api"))
            post_flow = next(f for f in flows if str(f.get("url")).endswith("/echo"))
            assert get_flow["method"] == "GET" and get_flow["status"] == 200
            assert post_flow["method"] == "POST"

            # flow_get must read the real response body back.
            got_detail = backend.flow_get("capture", str(get_flow["id"]), tmp_path)
            assert got_detail["request"]["method"] == "GET"
            assert "PROXY_FLOW_42" in got_detail["response"]["body"]

            # The POST's request body is the thing an API reverse-engineer wants;
            # it must survive capture, not be dropped.
            post_detail = backend.flow_get("capture", str(post_flow["id"]), tmp_path)
            assert "CLIENT_BODY_99" in post_detail["request"]["body"]

            # export_har must emit a valid HAR covering the captured flows.
            har = backend.export_har("capture", tmp_path / "capture.har")
            assert har["entry_count"] >= 2
            document = json.loads((tmp_path / "capture.har").read_text(encoding="utf-8"))
            assert document["log"]["entries"], "HAR must list the captured entries"

            # replay must re-issue a captured request through the running proxy.
            replayed = backend.replay("capture", str(get_flow["id"]))
            assert replayed["replayed"] is True
        finally:
            backend.close_all()
