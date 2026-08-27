"""Live CDP capture gate: the browser tools read a real page's real traffic.

``test_web_re_gate`` opens a data: URL and checks the page is reachable; it never
proves the DevTools capture surface an operator actually leans on. Serve a small
site with a subresource, a fetch, an external script and a console log, drive it
through the service the way a user would -- list network requests and pull one
back, list scripts and fetch a source, read the console, snap a screenshot,
export a HAR, then navigate -- and assert each returns the real bytes, not just
an ok flag. A data: URL issues no network requests and parses no external
script, so only a served origin can exercise these paths.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_SCRIPT_MARKER = "cdp-gate-script-MARKER"
_CONSOLE_MARKER = "cdp-gate-console-MARKER"
_NETWORK_MARKER = "gate-network-MARKER"
_SETTLE_S = 10.0

_APP_JS = (
    f"window.__marker = '{_SCRIPT_MARKER}';\n"
    f"console.log('{_CONSOLE_MARKER}');\n"
    "fetch('/data.json').then((r) => r.json());\n"
).encode()
_DATA_JSON = f'{{"cdp":"{_NETWORK_MARKER}"}}'.encode()
_INDEX = (
    b"<html><head><title>cdp-gate</title>"
    b"<script src='/app.js'></script></head>"
    b"<body><h1>hello cdp</h1></body></html>"
)
_PAGE2 = b"<html><head><title>second-page</title></head><body>two</body></html>"

_ROUTES = {
    "/app.js": (_APP_JS, "application/javascript"),
    "/data.json": (_DATA_JSON, "application/json"),
    "/page2": (_PAGE2, "text/html"),
}


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


class _SiteHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server dispatch name
        body, content_type = _ROUTES.get(self.path.split("?", 1)[0], (_INDEX, "text/html"))
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


@contextmanager
def _site() -> Iterator[str]:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_web_cdp_captures_network_scripts_console_and_media() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP capture Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _site() as origin:
            created = service.create_session(f"{origin}/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # The document, its external script and the fetch all show up as
                # separate requests; the fetch is async, so wait for it.
                deadline = time.monotonic() + _SETTLE_S
                requests: list[dict] = []
                while time.monotonic() < deadline:
                    listed = service.web_network_list(session_id, limit=100)
                    assert listed.ok, listed.error
                    requests = listed.data["requests"]
                    urls = [r["url"] for r in requests]
                    if any("app.js" in u for u in urls) and any("data.json" in u for u in urls):
                        break
                    time.sleep(0.1)
                urls = [r["url"] for r in requests]
                assert any(u.endswith("/") for u in urls), urls
                assert any("app.js" in u for u in urls), urls
                assert any("data.json" in u for u in urls), urls

                app_request = next(r for r in requests if "app.js" in r["url"])
                assert app_request["status"] == 200
                assert "javascript" in (app_request["mimeType"] or "")

                # network.get must return the actual response body over CDP.
                body = service.web_network_get(session_id, app_request["requestId"])
                assert body.ok, body.error
                assert _SCRIPT_MARKER in (body.data.get("body") or ""), body.data

                # The parsed external script is fetchable by its CDP scriptId,
                # and its source is the file the origin served.
                scripts = service.web_scripts(session_id, limit=100)
                assert scripts.ok, scripts.error
                app_script = next(
                    s for s in scripts.data["scripts"] if "app.js" in (s.get("url") or "")
                )
                source = service.web_script_source(session_id, app_script["scriptId"])
                assert source.ok, source.error
                assert _SCRIPT_MARKER in (source.data.get("source") or ""), source.data

                # console output is captured over CDP as plain data.
                deadline = time.monotonic() + _SETTLE_S
                console_texts: list[str] = []
                while time.monotonic() < deadline:
                    console = service.web_console(session_id, limit=200)
                    assert console.ok, console.error
                    console_texts = [c["text"] for c in console.data["console"]]
                    if any(_CONSOLE_MARKER in t for t in console_texts):
                        break
                    time.sleep(0.1)
                assert any(_CONSOLE_MARKER in t for t in console_texts), console_texts

                # A screenshot is a real PNG on disk, not an empty file.
                shot = service.web_screenshot(session_id)
                assert shot.ok, shot.error
                assert shot.data["size"] > 0
                assert Path(shot.data["path"]).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

                # The HAR carries the requests the page actually made.
                har = service.web_har_export(session_id)
                assert har.ok, har.error
                assert har.data["entry_count"] >= 3

                # Navigation moves the page and reports the new document.
                navigated = service.web_navigate(session_id, f"{origin}/page2")
                assert navigated.ok, navigated.error
                assert navigated.data["title"] == "second-page"
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
