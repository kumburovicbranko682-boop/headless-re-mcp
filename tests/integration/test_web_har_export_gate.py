"""Live web gate: har.export writes a well-formed HAR of the captured traffic.

The CDP capture gate checks only that some entry url made it into the HAR. That
leaves the shape untested: the HAR envelope, and whether the distinct resource
classes a page pulls -- the document, a linked script, an XHR/fetch -- each land
as an entry with a complete request/response. This gate loads a page that draws
all three, exports the HAR and asserts the envelope (version, creator, entries),
that every entry carries method/url/status/mimeType, and that Document, Script
and Fetch are all present with the right content types. It also pins the
export's own report (entry_count, truncated, size) against the file on disk.
skip != pass when playwright/chromium is missing.
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

_PAGE = (
    "<!doctype html><html><head><title>har</title>"
    '<script src="/app.js"></script></head>'
    "<body><h1>har gate</h1>"
    "<script>fetch('/data.json').then(r=>r.text())"
    ".then(t=>console.log('F='+t.length));</script>"
    "</body></html>"
)
_PAGES: dict[str, tuple[str, str]] = {
    "/page": (_PAGE, "text/html; charset=utf-8"),
    "/app.js": ("console.log('har-js');", "application/javascript; charset=utf-8"),
    "/data.json": ('{"k":"har-json"}', "application/json; charset=utf-8"),
}


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        body, ctype = _PAGES.get(self.path, ("not found", "text/plain; charset=utf-8"))
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

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


def _await_captured(backend: WebBackend, leaves: tuple[str, ...]) -> set[str]:
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        found = {
            leaf
            for req in backend.network_list("web")["requests"]
            for leaf in leaves
            if str(req.get("url")).endswith(leaf) and req.get("status") == 200
        }
        if found == set(leaves):
            return found
        time.sleep(0.1)
    return found


@pytest.mark.integration
def test_web_har_export_is_well_formed_across_resource_types(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web HAR Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    try:
        try:
            backend.open("web", f"http://127.0.0.1:{port}/page", headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        leaves = ("/page", "/app.js", "/data.json")
        assert _await_captured(backend, leaves) == set(leaves)

        out = tmp_path / "capture.har"
        report = backend.har_export("web", out)
        assert report["path"] == str(out)
        assert out.is_file()
        assert report["truncated"] is False, report
        # The reported size is the actual file length on disk.
        assert report["size"] == len(out.read_bytes()), report

        har = json.loads(out.read_text(encoding="utf-8"))
        log = har["log"]
        assert log["version"] == "1.2", log
        assert log["creator"]["name"] == "headless-re-mcp", log
        entries = log["entries"]
        assert isinstance(entries, list)
        assert len(entries) == report["entry_count"], (len(entries), report)

        # Every entry is complete: a request with a method and url, a response
        # with a status and a content mimeType.
        for entry in entries:
            assert entry["request"]["method"] == "GET", entry
            assert str(entry["request"]["url"]).startswith("http://127.0.0.1:"), entry
            assert isinstance(entry["response"]["status"], int), entry
            assert "mimeType" in entry["response"]["content"], entry

        by_leaf = {
            "/" + str(e["request"]["url"]).rsplit("/", 1)[-1]: e for e in entries
        }
        assert set(leaves) <= set(by_leaf), list(by_leaf)

        # The three resource classes a page pulls each land with the right type
        # and content type.
        page = by_leaf["/page"]
        assert page["_resourceType"] == "Document", page
        assert page["response"]["status"] == 200
        assert "text/html" in page["response"]["content"]["mimeType"], page

        script = by_leaf["/app.js"]
        assert script["_resourceType"] == "Script", script
        assert script["response"]["status"] == 200
        assert "javascript" in script["response"]["content"]["mimeType"], script

        data = by_leaf["/data.json"]
        # A fetch() is reported as Fetch by Chrome, XHR by older stacks.
        assert data["_resourceType"] in {"Fetch", "XHR"}, data
        assert data["response"]["status"] == 200
        assert "json" in data["response"]["content"]["mimeType"], data
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
