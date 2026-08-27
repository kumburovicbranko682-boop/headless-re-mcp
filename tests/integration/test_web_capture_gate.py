"""Web capture gate: CDP network/body/HAR/screenshot against a real local page.

The existing Web CDP gate drives scripts/console/dom on a ``data:`` URL, which
loads nothing over the wire, so the dynamic capture surface an MCP client leans
on -- ``web.network.list`` / ``web.network.get`` / ``web.har.export`` /
``web.screenshot`` / ``web.script.source`` -- never ran against real traffic.
Those all hang off CDP Network/Debugger events wired at open time, the kind of
protocol-version-sensitive plumbing that rots silently (the frida-17 memory-read
break was the same shape). This serves a page that pulls a subresource from a
throwaway ``http.server`` and proves each tool through ``AnalysisService``: the
document and script requests are captured with status and mime type, the script
body and source come back with the marker they were served with, the HAR file
parses with those entries, and the screenshot is real PNG bytes.

skip != pass: it skips only when the browser cannot launch.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PAGE_MARKER = "HELLO_WEB_CAPTURE_GATE"
_SCRIPT_MARKER = "WEBGATE_JS_9f2c"
_HTML = (
    "<!doctype html><html><head><title>capturegate</title></head>"
    f'<body><h1 id="marker">{_PAGE_MARKER}</h1>'
    '<script src="/app.js"></script></body></html>'
).encode()
_JS = f"console.log('{_SCRIPT_MARKER}');window.__gate=42;".encode()


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:  # keep the test output quiet
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        if self.path == "/app.js":
            body, content_type = _JS, "application/javascript"
        else:
            body, content_type = _HTML, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _wait_for_capture(service: AnalysisService, session_id: str) -> list[dict[str, Any]]:
    """Poll until the subresource request and its response status are recorded.

    CDP delivers requestWillBeSent and responseReceived asynchronously, so a
    single read right after navigation races the events.
    """
    deadline = time.monotonic() + 10.0
    requests: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        listed = service.web_network_list(session_id, limit=100)
        assert listed.ok, listed.error
        requests = listed.data["requests"]
        have_script = any("/app.js" in (r.get("url") or "") for r in requests)
        have_status = any(r.get("status") for r in requests)
        if have_script and have_status:
            return requests
        time.sleep(0.2)
    return requests


@pytest.mark.integration
def test_web_captures_network_body_har_and_screenshot(origin: str) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web capture Gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(origin, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            requests = _wait_for_capture(service, session_id)
            document = next(
                (r for r in requests if r.get("resourceType") == "Document"), None
            )
            script = next(
                (r for r in requests if "/app.js" in (r.get("url") or "")), None
            )
            assert document is not None, f"document request not captured: {requests}"
            assert script is not None, f"script request not captured: {requests}"
            assert document["status"] == 200
            assert script["status"] == 200
            assert "html" in (document.get("mimeType") or "")
            assert "javascript" in (script.get("mimeType") or "")

            # The response body must come back through CDP getResponseBody with
            # the exact bytes the origin served, not just request metadata.
            got = service.web_network_get(session_id, script["requestId"])
            assert got.ok, got.error
            assert _SCRIPT_MARKER in (got.data.get("body") or "")
            assert got.data.get("base64_encoded") is False

            # Debugger.getScriptSource is a separate CDP path from the body fetch.
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            parsed = next(
                (s for s in scripts.data["scripts"] if "/app.js" in (s.get("url") or "")),
                None,
            )
            assert parsed is not None, f"app.js not among parsed scripts: {scripts.data}"
            source = service.web_script_source(session_id, parsed["scriptId"])
            assert source.ok, source.error
            assert _SCRIPT_MARKER in (source.data.get("source") or "")

            # No wasm on this page: the filtered listing must resolve cleanly to
            # an empty set rather than erroring.
            wasm = service.web_wasm_list(session_id)
            assert wasm.ok, wasm.error
            assert wasm.data["count"] == 0

            # The HAR must be a real file that parses and carries both requests.
            har = service.web_har_export(session_id)
            assert har.ok, har.error
            har_doc = json.loads(Path(har.data["path"]).read_text(encoding="utf-8"))
            entries = har_doc["log"]["entries"]
            assert len(entries) >= 2
            har_urls = {e["request"]["url"] for e in entries}
            assert any(u.endswith("/app.js") for u in har_urls)
            assert all(e["response"]["status"] == 200 for e in entries)

            # A screenshot of a rendered page must be real PNG bytes.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            png = Path(shot.data["path"]).read_bytes()
            assert png[:8] == b"\x89PNG\r\n\x1a\n"
            assert shot.data["size"] > 0

            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert dom.data["title"] == "capturegate"
            assert _PAGE_MARKER in (dom.data.get("html") or "")
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
