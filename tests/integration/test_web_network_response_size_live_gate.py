"""web.network.list / web.har.export live gate: real decoded response body size.

The bug: the browser capture wired ``Network.requestWillBeSent`` and
``Network.responseReceived`` but never ``Network.dataReceived``, so no row and
no exported HAR entry carried the response body size. ``proxy.flows`` already
answers ``response_size``; the web line left an analyst unable to tell a small
response from a huge one without fetching every body, and the HAR wrote the -1
"unknown" sentinel for ``content.size``. ``Network.dataReceived.dataLength`` is
the decoded (uncompressed) byte count -- exactly what ``web.network.get`` hands
back as the body and what HAR ``content.size`` wants -- so summing it fills both.

This gate drives a real Chromium (through the same CDP path the tool uses) at a
local origin whose page pulls one sub-resource of a distinct, non-round size.
It then asserts ``web.network.list`` reports that exact decoded size for the
sub-resource's row and that the exported HAR entry's ``content.size`` and
``response.bodySize`` equal it too -- proving the byte count came from the real
``dataReceived`` stream, not a fabricated value. Guarding the guard: the size is
a specific number the origin alone chose (not 0, not the HTML's length), so a
pass means the real body bytes were measured. skip != pass: it skips only when
Chromium is genuinely unavailable.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# A distinct, non-round decoded body size the origin alone picks, so a matching
# assertion cannot be a coincidence with the HTML length or a zero default.
_ASSET_BYTES = 24571
_ASSET_PATH = "/asset.js"
_ASSET_BODY = ("//" + "a" * (_ASSET_BYTES - 2)).encode("ascii")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == _ASSET_PATH:
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(_ASSET_BODY)))
            self.end_headers()
            self.wfile.write(_ASSET_BODY)
            return
        if self.path == "/":
            body = (
                b"<html><head><title>size-gate</title>"
                b'<script src="' + _ASSET_PATH.encode("ascii") + b'"></script>'
                b"</head><body>hello</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


@contextmanager
def _origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


def _find_asset_row(service: AnalysisService, session_id: str) -> dict | None:
    listed = service.web_network_list(session_id, limit=200)
    assert listed.ok, listed.error
    for row in listed.data["requests"]:
        if str(row.get("url", "")).endswith(_ASSET_PATH):
            return row
    return None


@pytest.mark.integration
def test_web_network_and_har_report_the_decoded_response_size() -> None:
    if not _browser_available():
        pytest.skip("playwright/chromium not installed — web size gate not run (skip != pass)")

    service = AnalysisService()
    try:
        with _origin() as origin:
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
                asset_row: dict | None = None
                deadline = time.monotonic() + 25.0
                while time.monotonic() < deadline:
                    asset_row = _find_asset_row(service, session_id)
                    if asset_row is not None and int(asset_row.get("response_size") or 0) > 0:
                        break
                    time.sleep(0.25)

                assert asset_row is not None, "the sub-resource flow never appeared"
                assert asset_row["response_size"] == _ASSET_BYTES, asset_row

                exported = service.web_har_export(session_id)
                assert exported.ok, exported.error
                doc = json.loads(Path(exported.data["path"]).read_text(encoding="utf-8"))
                asset_entry = next(
                    e
                    for e in doc["log"]["entries"]
                    if str(e["request"]["url"]).endswith(_ASSET_PATH)
                )
                assert asset_entry["response"]["content"]["size"] == _ASSET_BYTES
                assert asset_entry["response"]["bodySize"] == _ASSET_BYTES
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
