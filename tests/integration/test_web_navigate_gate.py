"""Live gate for web.navigate: telemetry accumulates across a real navigation.

The lifecycle gate drives navigate for thread-safety and handle-leak checks, but
always to the same data: URL, so nothing proves navigate re-drives the page and
that a session's captured network, console and scripts accumulate across a move
from one real page to another rather than resetting. This gate serves two
distinct pages from a local origin, opens the first, navigates to the second,
and asserts both pages' traffic, console and scripts are retained while the live
views (status, dom_snapshot) track the current page. skip != pass when
playwright/chromium is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError

_MARK_A = "nav-marker-a-1a2b"
_MARK_B = "nav-marker-b-3c4d"
_PAGES: dict[str, tuple[str, str]] = {
    "/a": (
        "<!doctype html><html><head><title>page-a</title>"
        '<script src="/a.js"></script></head><body><h1>AAA</h1></body></html>',
        "text/html; charset=utf-8",
    ),
    "/b": (
        "<!doctype html><html><head><title>page-b</title>"
        '<script src="/b.js"></script></head><body><h1>BBB</h1></body></html>',
        "text/html; charset=utf-8",
    ),
    "/a.js": (f"console.log('{_MARK_A}');", "application/javascript; charset=utf-8"),
    "/b.js": (f"console.log('{_MARK_B}');", "application/javascript; charset=utf-8"),
}


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        key = self.path.split("?")[0]
        text, ctype = _PAGES.get(key, ("not found", "text/plain; charset=utf-8"))
        body = text.encode("utf-8")
        self.send_response(200 if key in _PAGES else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _wait_for(backend: WebBackend, suffix: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(str(r["url"]).endswith(suffix) for r in backend.network_list("nav")["requests"]):
            return
        time.sleep(0.1)


@pytest.mark.integration
def test_web_navigate_accumulates_telemetry_across_pages(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — navigate Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    base = f"http://127.0.0.1:{port}"
    try:
        try:
            opened = backend.open("nav", f"{base}/a", headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        assert opened["opened"] is True
        assert opened["title"] == "page-a"
        _wait_for(backend, "/a.js")

        # navigate re-drives goto and reports the new page's identity.
        moved = backend.navigate("nav", f"{base}/b", timeout=30.0)
        assert moved["title"] == "page-b", moved
        assert str(moved["url"]).endswith("/b"), moved
        _wait_for(backend, "/b.js")

        # Network capture retains both pages, not just the current one.
        urls = {str(r["url"]) for r in backend.network_list("nav")["requests"]}
        for suffix in ("/a", "/a.js", "/b", "/b.js"):
            assert any(u.endswith(suffix) for u in urls), (suffix, urls)
        by_url = {str(r["url"]): r for r in backend.network_list("nav")["requests"]}
        assert by_url[f"{base}/a.js"]["status"] == 200
        assert by_url[f"{base}/b.js"]["status"] == 200

        # Console lines from both pages survive the navigation.
        captured = backend.console("nav", limit=200)["console"]
        console_text = [str(item.get("text")) for item in captured]
        assert any(_MARK_A in t for t in console_text), console_text
        assert any(_MARK_B in t for t in console_text), console_text

        # Parsed scripts from both pages are retained.
        script_urls = {str(s["url"]) for s in backend.scripts("nav")["scripts"]}
        assert any(u.endswith("/a.js") for u in script_urls), script_urls
        assert any(u.endswith("/b.js") for u in script_urls), script_urls

        # The live views track the current page rather than the accumulated log.
        status = backend.status("nav")
        assert status["title"] == "page-b"
        assert str(status["url"]).endswith("/b")
        dom = backend.dom_snapshot("nav")
        assert dom["title"] == "page-b"
        assert "BBB" in dom["html"] and "AAA" not in dom["html"], dom
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
