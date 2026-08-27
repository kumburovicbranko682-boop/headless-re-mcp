"""Live gate for the web capture chain: network, HAR, screenshot, sources, wasm.

test_web_re_gate proves a CDP session opens and inspects a static page; this
gate proves the capture surfaces exist for real traffic. A loopback HTTP
server serves a page whose script fetches JSON and instantiates a WebAssembly
module, so every surface has ground truth to assert against: the fetched body
must round-trip byte for byte, the HAR must name the page/script/fetch
entries, the screenshot must be an actual PNG, the script source must come
back verbatim, and the module must appear in the WebAssembly-only script
listing -- with its exported call observed in the console, so the row
corresponds to code that really ran. Until this gate, none of web.navigate /
network.list / network.get / har.export / screenshot / script.source /
wasm.list had executable coverage. skip != pass: skips only when playwright
or its browser is unavailable.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# The same hand-encoded module the wabt gate uses: exports "answer" () -> i32
# returning 42. Embedding it gives the page a wasm instantiation with a result
# the console can prove.
_WASM_MODULE = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
        0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,  # type: () -> i32
        0x03, 0x02, 0x01, 0x00,  # function: uses type 0
        # export "answer" (func 0)
        0x07, 0x0A, 0x01, 0x06, 0x61, 0x6E, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00,
        0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,  # code: i32.const 42; end
    ]
)

_APP_JS = (
    "const bytes = new Uint8Array(["
    + ",".join(str(b) for b in _WASM_MODULE)
    + "]);\n"
    "const inst = new WebAssembly.Instance(new WebAssembly.Module(bytes));\n"
    "console.log('wasm-answer:' + inst.exports.answer());\n"
    "fetch('/data.json').then(r => r.json()).then(d => console.log('data:' + d.secret));\n"
    "// capture-gate-script-marker\n"
)

_PAGES: dict[str, tuple[str, bytes]] = {
    "/": (
        "text/html",
        b"<html><head><title>capture-gate</title>"
        b"<script src='/app.js'></script></head><body>hi</body></html>",
    ),
    "/app.js": ("application/javascript", _APP_JS.encode("utf-8")),
    "/data.json": ("application/json", json.dumps({"secret": "net-gate-payload"}).encode()),
    "/page2": ("text/html", b"<html><head><title>second</title></head><body>2</body></html>"),
}


class _SiteHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        mime, body = _PAGES.get(self.path, ("text/plain", b"not found"))
        self.send_response(200 if self.path in _PAGES else 404)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep the test output clean
        return


@pytest.fixture()
def site() -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


def _poll(check: Any, *, timeout: float = 15.0, message: str) -> Any:
    """Return check()'s first truthy value; capture events arrive asynchronously."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = check()
        if found:
            return found
        time.sleep(0.2)
    pytest.fail(message)


@pytest.mark.integration
def test_web_capture_chain_records_real_traffic(site: str) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — web capture Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(site + "/", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # network.list must record the fetch the page's script made,
            # complete with the response metadata CDP attaches later.
            def find_fetch_row() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id)
                assert listing.ok, listing.error
                for row in listing.data["requests"]:
                    if row.get("url", "").endswith("/data.json") and row.get("status") == 200:
                        return dict(row)
                return None

            row = _poll(find_fetch_row, message="the page's /data.json fetch was never recorded")
            assert row["method"] == "GET"
            assert row["mimeType"] == "application/json"

            # network.get must round-trip the body the server actually sent.
            body = service.web_network_get(session_id, row["requestId"])
            assert body.ok, body.error
            assert json.loads(body.data["body"]) == {"secret": "net-gate-payload"}
            assert body.data["base64_encoded"] is False
            assert body.data["body_truncated"] is False

            # har.export must write a document naming every captured exchange.
            exported = service.web_har_export(session_id)
            assert exported.ok, exported.error
            assert exported.data["entry_count"] >= 3
            har_path = Path(exported.data["path"])
            assert exported.data["size"] == har_path.stat().st_size
            document = json.loads(har_path.read_text(encoding="utf-8"))
            har_urls = {entry["request"]["url"] for entry in document["log"]["entries"]}
            assert {site + "/", site + "/app.js", site + "/data.json"} <= har_urls

            # screenshot must be a real PNG, not merely a file that exists.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            image = Path(shot.data["path"]).read_bytes()
            assert image[:8] == b"\x89PNG\r\n\x1a\n"
            assert shot.data["size"] == len(image)

            # script.source must hand back the code the server served.
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            app_rows = [
                s for s in scripts.data["scripts"] if s.get("url", "").endswith("/app.js")
            ]
            assert app_rows, f"/app.js never appeared in scripts: {scripts.data['scripts']}"
            source = service.web_script_source(session_id, app_rows[0]["scriptId"])
            assert source.ok, source.error
            assert "capture-gate-script-marker" in source.data["source"]

            # wasm.list must surface the instantiated module...
            def find_wasm_row() -> dict[str, Any] | None:
                listing = service.web_wasm_list(session_id)
                assert listing.ok, listing.error
                rows = listing.data["scripts"]
                return dict(rows[0]) if rows else None

            wasm_row = _poll(
                find_wasm_row, message="the instantiated wasm module never appeared"
            )
            assert wasm_row["language"] == "WebAssembly"
            # ...and the console proves that module really executed: 42 is
            # computed inside the wasm export, not in JS.
            console = service.web_console(session_id)
            assert console.ok, console.error
            texts = [entry.get("text", "") for entry in console.data["console"]]
            assert any("wasm-answer:42" in text for text in texts), texts

            # navigate must actually move the page and report where it landed.
            moved = service.web_navigate(session_id, site + "/page2")
            assert moved.ok, moved.error
            assert moved.data["url"] == site + "/page2"
            assert moved.data["status"] == 200
            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert dom.data["title"] == "second"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
