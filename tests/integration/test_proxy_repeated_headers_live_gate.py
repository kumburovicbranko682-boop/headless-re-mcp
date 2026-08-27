"""proxy.flow.get live gate: repeated response headers survive the round trip.

HTTP responses routinely carry a header name more than once -- most often
several ``Set-Cookie`` lines, one per cookie, which is exactly what a session or
auth analysis reaches for. mitmproxy keeps them as an ordered multimap, but the
backend used to render the header set as ``dict(headers)``, collapsing repeats
to the last value: a reverse engineer would see one cookie where the server set
several, and never know the others existed. flow.get now returns an ordered
``[{name, value}]`` list that keeps every occurrence.

Every ``_bounded_headers`` unit test drives a hand-written headers object, so
only a real mitmproxy proves that its ``items(multi=True)`` output is surfaced
faithfully once genuine traffic crosses the wire. The fixture is a throwaway
localhost origin whose response sets two distinct ``Set-Cookie`` headers, and
the request is sent through the proxy over plain HTTP, so the capture runs for
real with no external network and no CA-trust dance.

Skip != pass: the gate skips with a reason only when mitmproxy is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import http.server
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

_COOKIE_A = "session=PROXY_COOKIE_A; Path=/; HttpOnly"
_COOKIE_B = "tracking=PROXY_COOKIE_B; Path=/; Max-Age=3600"
_BODY = b'{"ok": true}'


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # Two Set-Cookie lines: the wire truth a dict header map would collapse.
        self.send_header("Set-Cookie", _COOKIE_A)
        self.send_header("Set-Cookie", _COOKIE_B)
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)


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


def _through_proxy(proxy_port: int, url: str) -> bytes:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    opener = urllib.request.build_opener(handler)
    with opener.open(url, timeout=15) as response:
        return bytes(response.read())


def _wait_for(predicate: Callable[[], bool], *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


@pytest.mark.integration
def test_flow_get_preserves_both_set_cookie_headers(tmp_path: Path) -> None:
    backend = ProxyBackend()
    try:
        backend._check_available()
    except ProxyError:
        pytest.skip("mitmproxy not installed — repeated-headers Gate not run (skip != pass)")

    port = _free_port()
    with _origin_site() as origin:
        started = backend.start("repeat-hdrs", port=port)
        assert started["running"] is True
        try:
            got = _through_proxy(port, f"{origin}/login")
            assert got == _BODY, "the origin body must reach the client via the proxy"

            assert _wait_for(lambda: backend.flows("repeat-hdrs", limit=100)["count"] >= 1), (
                "the proxy never recorded the request routed through it"
            )
            flows = backend.flows("repeat-hdrs", limit=100)["flows"]
            flow = next(f for f in flows if str(f.get("url")).endswith("/login"))

            detail = backend.flow_get("repeat-hdrs", str(flow["id"]), tmp_path)
            headers = detail["response"]["headers"]

            # The contract: an ordered list of {name, value} pairs, not a map.
            assert isinstance(headers, list)
            assert all(set(pair) == {"name", "value"} for pair in headers)

            # The fix: both Set-Cookie lines are present, in the order the origin
            # sent them. A dict header map kept only the second here.
            set_cookies = [
                h["value"] for h in headers if h["name"].lower() == "set-cookie"
            ]
            assert set_cookies == [_COOKIE_A, _COOKIE_B], set_cookies
        finally:
            backend.close_all()
