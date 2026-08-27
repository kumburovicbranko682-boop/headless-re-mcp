"""Live browser gate: web.scripts lists the page's scripts, not Playwright's.

Playwright injects a utility-world script into every frame it drives; those
surface via Debugger.scriptParsed with an empty URL and used to appear in
web.scripts as phantom entries. This opens a real page that loads one external
script and asserts two things a real browser must satisfy at once:

  * the page's own script (a real URL) is listed -- so the isolated-world filter
    does not over-reach and hide default-world scripts, and
  * no empty-URL entry survives -- so Playwright's injected instrumentation is
    gone.

skip != pass: runs whenever Playwright and Chromium are present, and only skips
when the browser is genuinely unavailable.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError

_PAGE = b"<!doctype html><html><head><title>scripts gate</title></head>" \
        b"<body><h1>gate</h1><script src=\"/app.js\"></script></body></html>"
_APP_JS = b"globalThis.__gate_marker = 'HEADLESS_SCRIPTS_GATE';\n"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:  # silence the access log
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/app.js":
            body, ctype = _APP_JS, "text/javascript"
        else:
            body, ctype = _PAGE, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _server() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


@pytest.mark.integration
def test_web_scripts_lists_page_scripts_and_drops_playwright_injection() -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web scripts Gate not run (skip != pass)")
    backend = WebBackend()
    with _server() as url:
        try:
            backend.open("scripts-gate", url, headless=True, timeout=30.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        try:
            # scriptParsed is asynchronous; give the page (and Playwright's own
            # injection) time to arrive before reading, so a regression to
            # including the phantom would actually be observed.
            time.sleep(1.5)
            payload = backend.scripts("scripts-gate", limit=100)
            urls = [s.get("url") for s in payload["scripts"]]
            assert any(str(u).endswith("/app.js") for u in urls), urls
            # The page authored no empty-URL script; any such entry is
            # Playwright's utility-world injection, which must be filtered.
            assert all(u for u in urls), f"an empty-URL phantom survived: {urls}"
        finally:
            backend.close("scripts-gate")
            backend.close_all()
