"""Web capture output live gate: real screenshots and a real browser HAR.

The web line's capture-extraction tools were gated before (network/scripts/
console/DOM), but two output surfaces were left running only against mocks:
``web.screenshot`` (a real PNG rendered by the browser through CDP) and
``web.har_export`` (the browser's *own* HAR, assembled from the CDP network
events it captured -- distinct from the proxy line's mitmproxy HAR). So the
screenshot encode/spill path and the HAR assembly from live requests were never
proven end to end.

This gate serves a tiny local site whose page loads a script that fetches a JSON
resource, drives a real headless Chromium over it, and then:

  * takes a viewport and a full-page screenshot, asserting each is a genuine PNG
    (magic bytes) whose reported size matches the file on disk; and
  * exports a HAR, parsing it back to assert it is a spec-shaped HAR 1.2 log whose
    entries include the document and the fetched resource, each with a GET request
    and a 200 response -- i.e. the browser really recorded those requests.

Skip != pass: the gate skips with a reason when Chromium/Playwright cannot launch,
and runs for real when present. CI installs the browser, so a skip there is a
genuine regression rather than a bare machine.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_MARKER = "WEB_HAR_MARKER"

_INDEX_HTML = (
    b"<!doctype html><html><head><title>har-gate</title></head><body>\n"
    b"<h1>capture output gate</h1>\n"
    b'<script src="/app.js"></script>\n'
    b"</body></html>"
)
_APP_JS = (
    b"fetch('/data.json').then(r => r.json())\n  .then(d => console.log('loaded ' + d.marker));\n"
)
_DATA_JSON = json.dumps({"marker": _MARKER}).encode("utf-8")

_ROUTES: dict[str, tuple[bytes, str]] = {
    "/": (_INDEX_HTML, "text/html"),
    "/app.js": (_APP_JS, "application/javascript"),
    "/data.json": (_DATA_JSON, "application/json"),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass

    def do_GET(self) -> None:
        body, ctype = _ROUTES.get(self.path, (b"not found", "text/plain"))
        self.send_response(200 if self.path in _ROUTES else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _local_site() -> Iterator[str]:
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _wait_for(predicate: Callable[[], bool], *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


@contextmanager
def _open_session(tmp_marker: str) -> Iterator[tuple[WebBackend, str]]:
    backend = WebBackend()
    with _local_site() as url:
        try:
            backend.open(tmp_marker, url, headless=True, timeout=30.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        try:
            # The fetch is async; the console line confirms the resource loaded so
            # the HAR/screenshot are taken after the page is fully populated.
            _wait_for(
                lambda: any(
                    "loaded " + _MARKER in str(c.get("text"))
                    for c in backend.console(tmp_marker, limit=100)["console"]
                )
            )
            yield backend, url
        finally:
            backend.close_all()


@pytest.mark.integration
def test_web_screenshot_writes_a_real_png(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — screenshot Gate not run (skip != pass)")

    with _open_session("shot") as (backend, _url):
        viewport = tmp_path / "viewport.png"
        result = backend.screenshot("shot", viewport)
        assert result["path"] == str(viewport)
        assert result["size"] > 0
        data = viewport.read_bytes()
        # A real browser screenshot is a PNG, and the reported size is the file's.
        assert data[:8] == _PNG_MAGIC
        assert len(data) == result["size"]

        full = tmp_path / "full.png"
        full_result = backend.screenshot("shot", full, full_page=True)
        assert full.read_bytes()[:8] == _PNG_MAGIC
        assert full_result["size"] > 0


@pytest.mark.integration
def test_web_har_export_records_the_documents_requests(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — HAR Gate not run (skip != pass)")

    with _open_session("har") as (backend, url):
        out = tmp_path / "capture.har"
        result = backend.har_export("har", out)
        assert result["path"] == str(out)
        assert out.is_file()

        har = json.loads(out.read_text(encoding="utf-8"))
        log = har["log"]
        # A spec-shaped HAR 1.2 log with a named creator.
        assert log["version"]
        assert log["creator"]["name"]
        entries = log["entries"]
        assert result["entry_count"] == len(entries)
        # The browser recorded both the document and the fetched JSON resource.
        urls = {str(e["request"]["url"]) for e in entries}
        assert any(u.rstrip("/") == url.rstrip("/") for u in urls), urls
        assert any("data.json" in u for u in urls), urls
        assert len(entries) >= 2
        # Each recorded request is a real GET that returned 200.
        for entry in entries:
            assert entry["request"]["method"] == "GET"
            assert entry["response"]["status"] == 200
