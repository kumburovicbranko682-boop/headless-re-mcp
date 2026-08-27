"""Live proxy replay gate: replaying a captured flow re-hits the origin.

The unit tests pin replay's error and timeout envelopes with mocks, but nothing
proves the command does what it claims -- re-send a captured request through the
proxy to the real server. This gate captures one flow, replays it, and asserts
the origin actually received a second request (a server-side counter, not just
the ``replayed: true`` envelope) and that the replay was itself recorded.
skip != pass when mitmproxy is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_BODY = b"REPLAY-GATE-BODY-3d9e"
_HITS: list[str] = []
_HITS_LOCK = threading.Lock()


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
        with _HITS_LOCK:
            _HITS.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _http_get_via_proxy(
    proxy_port: int, url: str, host_header: str, timeout: float = 10.0
) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        request = (
            f"GET {url} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def _hit_count() -> int:
    with _HITS_LOCK:
        return len(_HITS)


@pytest.mark.integration
def test_proxy_replay_resends_the_captured_request_to_the_origin() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")
    with _HITS_LOCK:
        _HITS.clear()

    origin_port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("replay", host="127.0.0.1", port=proxy_port)
    try:
        origin_url = f"http://127.0.0.1:{origin_port}/probe"
        raw = _http_get_via_proxy(proxy_port, origin_url, f"127.0.0.1:{origin_port}")
        assert b"200" in raw.split(b"\r\n", 1)[0], raw[:200]
        assert _BODY in raw, raw[:200]

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and backend.status("replay")["flow_count"] < 1:
            time.sleep(0.05)
        assert backend.status("replay")["flow_count"] == 1
        assert _hit_count() == 1, "origin should have been hit exactly once so far"

        flow = backend.flows("replay")["flows"][0]
        result = backend.replay("replay", flow["id"])
        # The envelope reports the command finished, not merely that it queued.
        assert result == {"replayed": True, "flow_id": flow["id"]}, result

        # The load-bearing proof: the origin actually received the request a
        # second time, so replay re-sent it rather than just echoing success.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _hit_count() < 2:
            time.sleep(0.05)
        assert _hit_count() == 2, "replay did not re-hit the origin"
        with _HITS_LOCK:
            assert _HITS == ["/probe", "/probe"], _HITS

        # The replayed request travels back through the proxy, so it is recorded
        # as a new flow rather than vanishing into the replay machinery.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and backend.status("replay")["flow_count"] < 2:
            time.sleep(0.05)
        assert backend.status("replay")["flow_count"] == 2
    finally:
        backend.stop("replay")
        origin.shutdown()
        origin.server_close()
