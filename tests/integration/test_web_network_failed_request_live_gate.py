"""web network capture live gate: a failed request is marked, not left pending.

A request that fails (connection refused, blocked, DNS, aborted) fires CDP's
``Network.loadingFailed``, never ``responseReceived`` -- so before the fix its
capture entry kept ``status: null`` with no other signal, exactly the shape of a
request still in flight. An analyst reading the capture could not tell a request
the browser refused from one it had not finished, and the unit tests only ever
built entries by hand so the live failure path was never exercised.

The capture now handles ``loadingFailed``, marking the entry ``failed: true`` and
carrying the browser's ``error_text``. This gate proves it against a real
headless Chromium by loading a page that issues two requests -- one to a closed
port (guaranteed to be refused) and one to a resource the server really serves --
and asserts:

  * the refused request's entry has ``failed`` true and an ``error_text`` naming a
    real network error (``net::ERR_...``), and its ``status`` stayed null; and
  * the served resource's entry has no ``failed`` key at all, so the marker is
    specific to real failures and a normal request is not tarred as failed.

Skip != pass: the gate skips with a reason when Playwright or its Chromium build
is absent. CI installs both, so a skip there is a real regression.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


def _closed_port() -> int:
    """A port with nothing listening, so a fetch to it is refused at once."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


_DEAD_PORT = _closed_port()
_OK_RESOURCE = b"window.__ok = 1;"
_DEAD_URL = f"http://127.0.0.1:{_DEAD_PORT}/dead"
_PAGE = (
    "<!doctype html><title>net</title>"
    "<script src='/ok.js'></script>"
    f"<script>fetch('{_DEAD_URL}').catch(() => {{}});</script>"
).encode()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # noqa: D401 - silence the server
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/ok.js":
            body, content_type = _OK_RESOURCE, "application/javascript"
        else:
            body, content_type = _PAGE, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.mark.integration
def test_failed_request_is_marked_while_a_served_one_is_not(base_url: str) -> None:
    backend = WebBackend()
    session_id = "web-network-failed-gate"
    try:
        backend.open(session_id, base_url, timeout=30.0)
    except WebError as exc:
        pytest.skip(f"web session could not open ({exc.code}: {exc}) — gate not run (skip != pass)")

    try:
        # Let the refused fetch reach loadingFailed and the served script land.
        deadline = time.monotonic() + 10.0
        dead = ok = None
        while time.monotonic() < deadline:
            requests = backend.network_list(session_id, limit=200)["requests"]
            dead = next((r for r in requests if "/dead" in str(r.get("url", ""))), None)
            ok = next((r for r in requests if "ok.js" in str(r.get("url", ""))), None)
            if dead is not None and dead.get("failed") and ok is not None:
                break
            time.sleep(0.2)

        assert dead is not None, "the refused request was never captured"
        # The fix: a refused request is marked failed, with the browser's reason,
        # and no HTTP status was ever received.
        assert dead.get("failed") is True, dead
        error_text = str(dead.get("error_text", ""))
        assert "net::ERR_" in error_text, error_text
        assert dead.get("status") is None, dead

        # The marker is specific to real failures: a request the server served
        # carries no failed key, so a normal request is never read as failed.
        assert ok is not None, "the served resource was never captured"
        assert "failed" not in ok, ok
        assert ok.get("status") == 200, ok
    finally:
        backend.close(session_id)
