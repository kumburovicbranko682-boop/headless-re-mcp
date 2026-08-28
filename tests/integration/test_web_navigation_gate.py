"""Live Web navigation gate: status surfacing, cross-document moves, console type.

``test_web_network_gate.py`` proves the capture buffers against a real origin, and
``test_web_re_gate.py`` opens a single ``data:`` URL. Neither proves the behaviour
this gate exists for, all of it against a real HTTP origin driven through the same
``web.*`` service API the tools use:

* **HTTP status surfacing** -- ``page.goto`` does not raise for a 4xx/5xx main
  document, so without ``_response_status`` a navigation onto an error page would
  report the same success as a real hit. The gate navigates onto a genuine 404
  and asserts the ``status`` comes back as ``404`` (the navigation still succeeds
  as a Result: the browser really did load that response). This is the error
  contract, and it had no live coverage.
* **Cross-document navigation** -- ``test_web_lifecycle_gate.py`` only re-navigates
  the *same* ``data:`` URL, so it never proves ``web.navigate`` moves to a
  *different* document. Here two distinct routes give distinct titles/URLs/bodies.
* **console message type** -- the existing CDP gate asserts only that
  ``web.console`` returns ``ok``; nothing checks it captured a specific line or
  mapped ``console.error`` to ``type="error"`` rather than a generic ``log``.
* **DOM snapshot body** -- the existing gate checks only the ``title``; here the
  snapshot must carry the navigated document's body marker, with ``truncated`` False
  for a small page.

skip != pass: skips only when Playwright or a launchable Chromium is genuinely
absent, never silently.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# Each route carries a distinct title and body marker so a navigation can be told
# apart from the one before it, and page one logs on both console channels so the
# type mapping (log vs error) can be checked.
_PAGE_ONE = (
    b"<!doctype html><html><head><title>nav-gate-one</title>"
    b"<script>console.log('NAV-ONE-LOG');console.error('NAV-ONE-ERR');</script>"
    b"</head><body>BODY-ONE-MARKER</body></html>"
)
_PAGE_TWO = (
    b"<!doctype html><html><head><title>nav-gate-two</title></head>"
    b"<body>BODY-TWO-MARKER</body></html>"
)
# Served with a real 404 so the status-surfacing assertion is about an HTTP error
# code, not a transport failure (which would raise instead of resolving).
_PAGE_MISSING = (
    b"<!doctype html><html><head><title>nav-gate-missing</title></head>"
    b"<body>NOT-FOUND-MARKER</body></html>"
)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path == "/second":
            body, status = _PAGE_TWO, 200
        elif path == "/missing":
            body, status = _PAGE_MISSING, 404
        else:
            body, status = _PAGE_ONE, 200
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence the stdlib access log
        return


@contextmanager
def _local_origin() -> Iterator[int]:
    """A throwaway HTTP origin on localhost, torn down on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, name="gate-web-nav-origin", daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _await_console(service: AnalysisService, session_id: str, text: str) -> list[dict]:
    """Return the console buffer once ``text`` appears, or the last read on timeout.

    Runtime.consoleAPICalled is delivered asynchronously, so a line logged during
    the document parse can trail the navigation's return by a beat -- the same
    async gap the network gate polls the request status for.
    """
    deadline = time.monotonic() + 10.0
    entries: list[dict] = []
    while time.monotonic() < deadline:
        result = service.web_console(session_id, limit=500)
        assert result.ok, result.error
        entries = list(result.data["console"])
        if any(str(item.get("text")) == text for item in entries):
            return entries
        time.sleep(0.1)
    return entries


@pytest.mark.integration
def test_web_navigation_surfaces_status_and_moves_documents() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web navigation Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _local_origin() as origin_port:
            base = f"http://127.0.0.1:{origin_port}"
            created = service.create_session(base + "/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Opening a real HTTP origin surfaces the 200 the server sent, not
                # just an "opened" flag -- the same _response_status path navigate
                # uses, proven first on the success case.
                assert opened.data["title"] == "nav-gate-one", opened.data
                assert opened.data.get("status") == 200, opened.data

                # console captured both channels page one logged, and console.error
                # is a distinct type, not folded into a generic "log".
                entries = _await_console(service, session_id, "NAV-ONE-ERR")
                by_text = {str(e.get("text")): str(e.get("type")) for e in entries}
                assert by_text.get("NAV-ONE-LOG") == "log", entries
                assert by_text.get("NAV-ONE-ERR") == "error", entries

                # Moving to a different document changes URL, title and status --
                # the same-URL re-navigation the lifecycle gate does never showed
                # navigate actually lands somewhere new.
                second = service.web_navigate(session_id, base + "/second", timeout=30.0)
                assert second.ok, second.error
                assert second.data["url"].endswith("/second"), second.data
                assert second.data["title"] == "nav-gate-two", second.data
                assert second.data.get("status") == 200, second.data

                # The DOM snapshot carries the *body* of the document just
                # navigated to, not merely its title, and a small page is not
                # marked truncated.
                dom = service.web_dom_snapshot(session_id)
                assert dom.ok, dom.error
                assert dom.data["title"] == "nav-gate-two", dom.data
                assert "BODY-TWO-MARKER" in dom.data["html"], dom.data["html"][:200]
                assert dom.data["truncated"] is False, dom.data

                # The centrepiece: a 404 main document is a successful Result whose
                # status is the real 404. goto does not raise for HTTP errors, so
                # without _response_status this would look identical to a 200 hit.
                missing = service.web_navigate(session_id, base + "/missing", timeout=30.0)
                assert missing.ok, missing.error
                assert missing.data["url"].endswith("/missing"), missing.data
                assert missing.data.get("status") == 404, missing.data
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
