"""Web dynamic gate: real CDP network capture, HAR, DOM and screenshot on Linux.

test_web_re_gate.py opens a data: URL and checks scripts/console/dom, which never
exercises the parts of the Web line that matter for real analysis: network flows
captured over CDP, a request body fetched back, a HAR exported and re-read, a DOM
snapshot and a screenshot landing as registered artifacts. Those had no gate that
runs anywhere.

This gate stands up a throwaway localhost HTTP server (so there is real traffic:
an HTML document, an external script, and a fetched JSON endpoint), drives the
whole web.* surface through AnalysisService against a headless Chromium, and
asserts the captured content is real -- the fetched body carries its marker, the
HAR round-trips as JSON whose entry count matches, the screenshot is a real PNG.

Skips with an explicit "skip != pass" when Playwright or its browser is absent;
verified against the Playwright-managed Chromium headless shell on Linux.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_TITLE = "headless-re web gate"
_CONSOLE_MARKER = "gate-console-marker"
_JSON_MARKER = "gate-json-marker"

_INDEX = (
    "<!doctype html><html><head><title>" + _TITLE + "</title>"
    '<script src="/app.js"></script>'
    "<script>console.log('" + _CONSOLE_MARKER + "');"
    "fetch('/api/data.json').then(r=>r.json()).then(d=>{window.__ok=d.ok;});"
    "</script></head><body><h1>hello gate</h1><p id='body'>content</p></body></html>"
).encode()
_APP_JS = b"window.__app = function () { return 42; };\n"
_DATA_JSON = json.dumps({"ok": True, "marker": _JSON_MARKER}).encode()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence the default stderr log
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/app.js":
            body, ctype = _APP_JS, "application/javascript"
        elif self.path.startswith("/api/data.json"):
            body, ctype = _DATA_JSON, "application/json"
        else:
            body, ctype = _INDEX, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


def _poll(predicate, *, timeout: float = 12.0, interval: float = 0.4) -> bool:
    """Give the browser a moment: CDP events land asynchronously after open."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@pytest.mark.integration
def test_web_dynamic_capture_roundtrip() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web Dynamic Gate not run (skip != pass)")

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/"

    service = AnalysisService()
    try:
        created = service.create_session(base, target="web")
        assert created.ok, created.error
        assert created.data["session"]["target"] == "web"
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        assert opened.data["url"].startswith(base)
        assert opened.data["title"] == _TITLE

        # The document, the external script and the fetched endpoint must all
        # show up in the CDP-captured request list.
        def _has_all_requests() -> bool:
            listed = service.web_network_list(session_id, limit=100)
            if not listed.ok:
                return False
            urls = {req["url"] for req in listed.data["requests"]}
            return any("app.js" in u for u in urls) and any("data.json" in u for u in urls)

        assert _poll(_has_all_requests), "network capture never saw app.js and data.json"

        listed = service.web_network_list(session_id, limit=100)
        assert listed.ok, listed.error
        requests = listed.data["requests"]
        assert listed.data["count"] >= 3
        sample = requests[0]
        for field in ("requestId", "url", "method", "status", "mimeType"):
            assert field in sample, f"network item missing {field}"

        # Fetch one captured response body back and confirm it is the real thing.
        data_request = next(req for req in requests if "data.json" in req["url"])
        body = service.web_network_get(session_id, data_request["requestId"])
        assert body.ok, body.error
        assert body.data["status"] == 200
        assert "json" in body.data["mimeType"]
        assert _JSON_MARKER in json.dumps(body.data)

        # An unknown request id is not_found, not a crash or an empty body.
        missing = service.web_network_get(session_id, "no-such-request-id")
        assert not missing.ok
        assert missing.error is not None
        assert missing.error.code == "not_found"

        # The page's console line was captured verbatim.
        assert _poll(
            lambda: any(
                _CONSOLE_MARKER in str(entry.get("text", ""))
                for entry in service.web_console(session_id).data.get("console", [])
            )
        ), "console marker never captured"

        scripts = service.web_scripts(session_id)
        assert scripts.ok, scripts.error
        assert scripts.data["count"] >= 1
        assert any("app.js" in str(item.get("url", "")) for item in scripts.data["scripts"])

        dom = service.web_dom_snapshot(session_id)
        assert dom.ok, dom.error
        assert dom.data["title"] == _TITLE
        assert "hello gate" in dom.data["html"]

        # A screenshot lands as a registered artifact that is a real PNG on disk.
        shot = service.web_screenshot(session_id)
        assert shot.ok, shot.error
        assert shot.data["size"] > 0
        shot_path = Path(shot.data["path"])
        assert shot_path.is_file()
        assert shot_path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

        # The HAR export round-trips as JSON whose entry count matches the reply.
        har = service.web_har_export(session_id)
        assert har.ok, har.error
        assert har.data["entry_count"] >= 1
        har_doc = json.loads(Path(har.data["path"]).read_text(encoding="utf-8"))
        assert har.data["entry_count"] == len(har_doc["log"]["entries"])

        # A non-positive navigation timeout is refused before it can wedge the
        # live session.
        bad_nav = service.web_navigate(session_id, base, timeout=0)
        assert not bad_nav.ok
        assert bad_nav.error is not None
        assert bad_nav.error.code == "invalid_params"

        closed = service.web_close(session_id)
        assert closed.ok, closed.error
    finally:
        service.close_all()
        server.shutdown()
