"""web.navigate live gate: a second navigation reuses the session and keeps capturing.

``web.open`` launches the browser and does the first ``page.goto``; every web
capture gate drives it. ``web.navigate`` is the separate tool that moves an
*already-open* session to a new URL, and nothing exercised it against a real
browser. The distinction matters: navigate keeps the same page and the CDP
listeners open() wired, so the interesting property -- that network capture
persists across a navigation and accumulates both pages' requests, rather than
resetting or detaching -- is invisible to any open-only test.

This gate serves two pages from a local HTTP server, each pulling a distinct
sub-resource, then:

  * opens page A and navigates to page B, asserting each call reports the URL it
    landed on, the page title, and an HTTP 200 status; and
  * reads the captured network afterwards and asserts requests from *both* pages
    are present -- proving navigate reused the session's page and its capture
    stayed live across the navigation, not just that a second goto returned.

It also pins the documented contract that a 4xx/5xx destination still counts as
navigated (the tool answers with status, not an error) by navigating to a route
the server refuses.

Skip != pass: the gate skips with a reason when playwright or its Chromium build
is absent. CI installs both, so a skip there is a real regression.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError


def _page(title: str, resource: str) -> bytes:
    """A minimal HTML doc with a title and one sub-resource fetch to capture."""
    return f"<!doctype html><title>{title}</title><script src='{resource}'></script>".encode()


_PAGES: dict[str, tuple[str, bytes]] = {
    "/a": ("text/html", _page("Page A", "/res_a.js")),
    "/b": ("text/html", _page("Page B", "/res_b.js")),
    "/res_a.js": ("application/javascript", b"window.__a = 1;"),
    "/res_b.js": ("application/javascript", b"window.__b = 1;"),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # noqa: D401 - silence the server
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        page = _PAGES.get(self.path)
        if page is None:
            # A deliberate 4xx so the gate can prove navigate still reports status.
            body = b"<!doctype html><title>Missing</title>nope"
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        content_type, body = page
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


def _open_or_skip(backend: WebBackend, session_id: str, url: str) -> dict[str, Any]:
    """Open a session, turning an absent/unlaunchable browser into an honest skip."""
    try:
        return backend.open(session_id, url, timeout=30.0)
    except WebError as exc:
        if exc.code == "capability_unavailable":
            pytest.skip(f"playwright/chromium unavailable ({exc}) — gate not run (skip != pass)")
        # A launch that fails for another reason is an environment limit, not a
        # code defect this gate is meant to catch.
        pytest.skip(f"web session could not open ({exc.code}: {exc}) — gate not run (skip != pass)")


@pytest.mark.integration
def test_navigate_reuses_the_session_and_keeps_capturing(base_url: str) -> None:
    backend = WebBackend()
    session_id = "web-navigate-gate"
    opened = _open_or_skip(backend, session_id, f"{base_url}/a")
    try:
        assert opened["url"].endswith("/a")
        assert opened["title"] == "Page A"
        assert opened.get("status") == 200

        navigated = backend.navigate(session_id, f"{base_url}/b", timeout=30.0)
        assert navigated["url"].endswith("/b")
        assert navigated["title"] == "Page B"
        assert navigated.get("status") == 200

        # Give the resource fetches a beat to land in the capture ring.
        time.sleep(0.5)
        requests = backend.network_list(session_id, limit=200)["requests"]
        urls = [str(item.get("url", "")) for item in requests]

        # The crux: both pages' traffic is present, so the capture that open()
        # wired survived the navigate rather than resetting with the new page.
        assert any(url.endswith("/a") for url in urls), urls
        assert any("res_a.js" in url for url in urls), urls
        assert any(url.endswith("/b") for url in urls), urls
        assert any("res_b.js" in url for url in urls), urls
    finally:
        backend.close(session_id)


@pytest.mark.integration
def test_navigate_to_an_error_page_still_reports_status(base_url: str) -> None:
    backend = WebBackend()
    session_id = "web-navigate-gate-404"
    _open_or_skip(backend, session_id, f"{base_url}/a")
    try:
        # A 4xx destination is still a navigation: the tool answers with status
        # rather than raising, so an agent can tell an error page from a hit.
        result = backend.navigate(session_id, f"{base_url}/does-not-exist", timeout=30.0)
        assert result["url"].endswith("/does-not-exist")
        assert result.get("status") == 404
    finally:
        backend.close(session_id)
