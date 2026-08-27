"""Live proxy capture gate: real traffic is intercepted, recorded, retrievable.

The lifecycle gate proves start/stop/port behaviour but never sends a byte
through the proxy, so ``flow_count`` is only ever asserted to be 0 and the whole
point of an interception proxy -- recording and handing back the traffic -- goes
untested. This gate stands up a local origin, routes a real HTTP request through
mitmproxy to it, and asserts the flow is recorded, listed, its body retrievable
and exported to HAR. skip != pass when mitmproxy is missing.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_BODY = b"PROXY-GATE-BODY-4f2a"


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
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _http_get_via_proxy(
    proxy_host: str, proxy_port: int, url: str, host_header: str, timeout: float = 10.0
) -> bytes:
    """Speak plain HTTP to the forward proxy with an absolute-form request line.

    A raw socket avoids urllib/httpx localhost proxy-bypass quirks, so the
    request is guaranteed to traverse mitmproxy rather than hit the origin
    directly.
    """
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        request = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


@pytest.mark.integration
def test_proxy_captures_a_real_flow_and_exports_har(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    origin_port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    started = backend.start("capture", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        origin_url = f"http://127.0.0.1:{origin_port}/probe"
        raw = _http_get_via_proxy(
            "127.0.0.1", proxy_port, origin_url, f"127.0.0.1:{origin_port}"
        )
        # The proxied response reaches the client intact.
        assert b"200" in raw.split(b"\r\n", 1)[0], raw[:200]
        assert _BODY in raw, raw[:400]

        # The recorder addon fires on the finished response; give it a moment.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and backend.status("capture")["flow_count"] < 1:
            time.sleep(0.05)
        assert backend.status("capture")["flow_count"] >= 1

        listed = backend.flows("capture")
        assert listed["total"] >= 1
        flow = listed["flows"][0]
        assert flow["method"] == "GET"
        assert f"127.0.0.1:{origin_port}" in flow["url"], flow
        assert flow["status"] == 200

        # flow_get returns the recorded response, body and all.
        detail = backend.flow_get("capture", flow["id"], tmp_path / "artifacts")
        assert detail["request"]["method"] == "GET"
        assert detail["response"]["status"] == 200
        assert _BODY.decode() in detail["response"]["body"], detail

        # HAR export carries the same request through to a file.
        har_path = tmp_path / "capture.har"
        exported = backend.export_har("capture", har_path)
        assert exported["entry_count"] >= 1
        har = json.loads(har_path.read_text(encoding="utf-8"))
        urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
        assert any(f"127.0.0.1:{origin_port}" in url for url in urls), urls
    finally:
        backend.stop("capture")
        origin.shutdown()
        origin.server_close()
