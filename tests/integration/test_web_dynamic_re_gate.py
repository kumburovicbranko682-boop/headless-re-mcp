"""Live web dynamic RE gate: fetch what a real page actually served.

The existing web gates prove the browser opens, closes cleanly, and lists its
scripts/console/DOM. They never prove the operations an analyst reaches a
headless browser *for*: pull the exact JavaScript a page loaded, read a response
body byte for byte, screenshot the rendered page, and export the network log.
Those all round-trip through CDP against a live Chromium, and none of them had a
single line of live execution coverage -- the whole "read what the page did"
half of the web line was skip != pass.

This gate stands up a real HTTP origin, drives one Chromium session through the
service layer (so artifact registration and the capture caps ride along too),
and asserts each read recovers the real bytes:

* ``web.network.get`` on the HTML document and the script returns their text
  bodies inline, not base64;
* ``web.network.get`` on the PNG returns ``base64_encoded`` with the body spilled
  to a file whose bytes are the *decoded* image at its real length -- the path a
  past bug wrote base64 text into, measured against the ~33% larger encoded size;
* ``web.script.source`` recovers the external script's source, marker and all;
* ``web.screenshot`` writes a real PNG;
* ``web.har.export`` emits every captured request.

Chromium is the only moving part that may be absent; when it cannot launch the
gate skips with an explicit message rather than passing on nothing.
"""

from __future__ import annotations

import http.server
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.core.service import AnalysisService

# A 1x1 PNG. Binary, well under any inline cap, and it must come back through
# network.get as decoded bytes -- never as the base64 string CDP hands over.
_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6360000002000154a24f5f0000000049454e44ae426082"
)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# A recognisable token the deobfuscation-free source read must recover verbatim.
_SCRIPT_MARKER = "SECRET_TOKEN_9f"
_JS = (
    f"function __gate_marker() {{ return '{_SCRIPT_MARKER}'; }}\n"
    "window.__x = __gate_marker();\n"
).encode()
_HTML = (
    b"<html><head><title>dyn-gate</title>"
    b"<script src='/app.js'></script></head>"
    b"<body><h1>hello dynamic re</h1><img src='/pixel.png'></body></html>"
)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # keep the test output clean
        pass

    def do_GET(self) -> None:  # noqa: N802 - http.server's required name
        if self.path.startswith("/app.js"):
            body, content_type = _JS, "application/javascript"
        elif self.path.startswith("/pixel.png"):
            body, content_type = _PNG, "image/png"
        else:
            body, content_type = _HTML, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def origin() -> Iterator[str]:
    """A throwaway localhost origin serving the document, script and image."""
    server = http.server.HTTPServer(("127.0.0.1", _free_port()), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _requests_by_url(service: AnalysisService, session_id: str) -> dict[str, dict[str, Any]]:
    """Poll network.list until the document, script and image have all arrived.

    A page load fans out into several CDP requests that do not all land in one
    tick; keying by URL suffix lets the gate wait for the three it serves
    without caring what order Chromium reports them in.
    """
    deadline = time.monotonic() + 15.0
    wanted = ("/", "/app.js", "/pixel.png")
    while True:
        listing = service.web_network_list(session_id, limit=100)
        assert listing.ok, listing.error
        found: dict[str, dict[str, Any]] = {}
        for row in listing.data["requests"]:
            url = str(row.get("url", ""))
            for suffix in wanted:
                key = suffix.rsplit("/", 1)[-1] or "document"
                if url.endswith(suffix):
                    found[key] = row
        if len(found) == len(wanted) or time.monotonic() >= deadline:
            return found
        time.sleep(0.2)


@pytest.mark.integration
def test_web_reads_back_the_bytes_a_live_page_served(origin: str, tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — Web dynamic RE Gate not run (skip != pass)")

    service = AnalysisService()
    try:
        created = service.create_session(origin, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=45.0)
        if not opened.ok:
            code = opened.error.code if opened.error else "unknown"
            pytest.skip(f"chromium could not launch ({code}) — Gate not run (skip != pass)")

        rows = _requests_by_url(service, session_id)
        assert {"document", "app.js", "pixel.png"} <= set(rows), sorted(rows)
        assert rows["document"]["status"] == 200
        assert "javascript" in str(rows["app.js"]["mimeType"]).lower()
        assert str(rows["pixel.png"]["mimeType"]).lower() == "image/png"

        # --- text bodies come back inline, decoded, not base64 ---
        document = service.web_network_get(session_id, rows["document"]["requestId"])
        assert document.ok, document.error
        assert document.data["base64_encoded"] is False
        assert "hello dynamic re" in document.data["body"]

        script_body = service.web_network_get(session_id, rows["app.js"]["requestId"])
        assert script_body.ok, script_body.error
        assert script_body.data["base64_encoded"] is False
        assert _SCRIPT_MARKER in script_body.data["body"]

        # --- the binary body is decoded to real bytes and spilled, never inlined ---
        image = service.web_network_get(session_id, rows["pixel.png"]["requestId"])
        assert image.ok, image.error
        assert image.data["base64_encoded"] is True
        assert image.data["body"] == "", "a binary body must not be inlined as text"
        # The reported length is the decoded image, not the ~33% larger base64.
        assert image.data["body_bytes"] == len(_PNG), image.data
        spilled = Path(image.data["body_path"])
        assert spilled.is_file(), image.data
        assert spilled.read_bytes() == _PNG, "spilled body must be the decoded image bytes"

        # --- the external script's source is recoverable by scriptId ---
        scripts = service.web_scripts(session_id, limit=200)
        assert scripts.ok, scripts.error
        script_id = next(
            (
                str(entry["scriptId"])
                for entry in scripts.data["scripts"]
                if str(entry.get("url", "")).endswith("/app.js")
            ),
            None,
        )
        assert script_id is not None, scripts.data["scripts"]
        source = service.web_script_source(session_id, script_id)
        assert source.ok, source.error
        assert _SCRIPT_MARKER in source.data["source"]
        assert source.data["bytes"] > 0

        # --- a real screenshot of the rendered page ---
        shot = service.web_screenshot(session_id)
        assert shot.ok, shot.error
        assert shot.data["size"] > 0
        assert Path(shot.data["path"]).read_bytes()[:8] == _PNG_SIGNATURE

        # --- the network log exports every request that was served ---
        har = service.web_har_export(session_id)
        assert har.ok, har.error
        assert har.data["entry_count"] >= 3
        har_urls = _har_urls(Path(har.data["path"]))
        assert any(url.endswith("/app.js") for url in har_urls), har_urls
        assert any(url.endswith("/pixel.png") for url in har_urls), har_urls
    finally:
        service.close_all()


def _har_urls(path: Path) -> list[str]:
    import json

    doc = json.loads(path.read_text(encoding="utf-8"))
    return [str(entry["request"]["url"]) for entry in doc["log"]["entries"]]
