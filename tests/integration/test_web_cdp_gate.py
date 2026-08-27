"""Live web CDP capture gate: a real page's network, script, console and DOM.

The browser lifecycle gate drives only ``data:`` URLs, which make no network
requests, so network_list / network_get / har_export and console capture were
never exercised against real traffic. This gate serves a small HTML page that
links a script from a local origin, opens it in Chromium over CDP, and asserts
the document and script requests are recorded with status and resource type,
the script's response body is retrievable through getResponseBody, the console
line the script logs is captured, and the DOM snapshot and HAR export both carry
the page. skip != pass when playwright/chromium is missing.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError

_MARKER = "w3b-cdp-marker-91c3"
_PAGE = (
    "<!doctype html><html><head><title>cdp-gate</title>"
    '<script src="/app.js"></script></head>'
    "<body><h1>cdp gate body</h1></body></html>"
)
_APP_JS = f"console.log('{_MARKER}'); window.__marker = '{_MARKER}';"


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path.startswith("/app.js"):
            text, ctype = _APP_JS, "application/javascript; charset=utf-8"
        else:
            text, ctype = _PAGE, "text/html; charset=utf-8"
        body = text.encode("utf-8")
        self.send_response(200)
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


@pytest.mark.integration
def test_web_cdp_captures_network_console_and_dom(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web CDP Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    url = f"http://127.0.0.1:{port}/page"
    try:
        try:
            opened = backend.open("cdp", url, headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        assert opened["opened"] is True
        assert opened["title"] == "cdp-gate"

        # The document request is captured during open; the script response may
        # land a beat later, so wait briefly for it before asserting.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            requests = backend.network_list("cdp")["requests"]
            if any(str(r["url"]).endswith("/app.js") and r["status"] for r in requests):
                break
            time.sleep(0.1)

        listed = backend.network_list("cdp")
        assert listed["total"] >= 2, listed
        by_url = {str(r["url"]): r for r in listed["requests"]}

        doc = next(r for u, r in by_url.items() if u.endswith("/page"))
        assert doc["status"] == 200
        assert str(doc["mimeType"] or "").startswith("text/html"), doc
        assert str(doc["resourceType"]).lower() == "document", doc

        js = next(r for u, r in by_url.items() if u.endswith("/app.js"))
        assert js["status"] == 200
        assert str(js["resourceType"]).lower() == "script", js

        # The script's response body comes back through CDP getResponseBody.
        detail = backend.network_get("cdp", str(js["requestId"]), tmp_path / "artifacts")
        assert _MARKER in str(detail.get("body", "")), detail

        # The console line the script logged is captured over CDP.
        console = backend.console("cdp", limit=200)
        assert any(_MARKER in str(item.get("text")) for item in console["console"]), console

        # The DOM snapshot carries the rendered document.
        dom = backend.dom_snapshot("cdp")
        assert dom["title"] == "cdp-gate"
        assert "cdp gate body" in dom["html"], dom

        # HAR export carries the same requests through to a file.
        har_path = tmp_path / "web.har"
        exported = backend.har_export("cdp", har_path)
        assert exported["entry_count"] >= 2
        har = json.loads(har_path.read_text(encoding="utf-8"))
        har_urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
        assert any(str(u).endswith("/app.js") for u in har_urls), har_urls
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
