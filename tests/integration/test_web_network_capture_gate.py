"""Web CDP capture gate: a real response body is extracted and HAR'd.

``test_web_cdp_open_and_inspect`` drives ``web.open`` / ``scripts`` / ``console``
/ ``dom_snapshot`` against a ``data:`` URL, but it stops there: nothing fetches a
response body or exports a HAR. That leaves the two primitives the Web track
actually leans on for extraction untested live -- ``web.network_get`` (CDP
``Network.getResponseBody``, the only way to pull a response body out of a live
page) and ``web.har_export``. Both are version-sensitive CDP/Playwright
surfaces: a protocol or driver drift there (the runtime-only class of break)
would pass every fake-based test and only fail against a real browser.

This gate stands up a throwaway same-origin HTTP server whose page ``fetch()``es
a JSON endpoint, opens it through the real CDP browser, then pins that the
sub-resource request is captured, that ``network_get`` decodes the endpoint's
real body (not a redirect stub or a base64 mangle), and that ``har_export``
emits a matching entry. Skips (skip != pass) when Playwright / Chromium is not
installed.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_MARKER = "web-netcapture-marker-4f9a2c"
_ENDPOINT = "/api/data"
_BODY = json.dumps({"marker": _MARKER, "ok": True})

_PAGE = (
    "<!doctype html><html><head><title>netgate</title></head>"
    "<body>hello"
    "<script>"
    f"fetch('{_ENDPOINT}').then(r => r.text()).then(t => {{ window.__netgate = t; }});"
    "</script>"
    "</body></html>"
)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path.split("?", 1)[0] == _ENDPOINT:
            body = _BODY.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = _PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass  # keep the test output quiet


@pytest.mark.integration
def test_web_network_get_and_har_over_a_real_response() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web capture Gate not run (skip != pass)")

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    origin_port = origin.server_address[1]
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    service = AnalysisService()
    try:
        url = f"http://127.0.0.1:{origin_port}/"
        created = service.create_session(url, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )

        # The fetch fires after DOMContentLoaded, so the sub-resource request
        # arrives a beat after web.open returns. Poll for it rather than assuming
        # instant delivery.
        deadline = time.monotonic() + 15.0
        endpoint_req: dict | None = None
        while time.monotonic() < deadline:
            listed = service.web_network_list(session_id, limit=1000)
            assert listed.ok, listed.error
            endpoint_req = next(
                (
                    r
                    for r in listed.data["requests"]
                    if str(r.get("url", "")).endswith(_ENDPOINT)
                    and r.get("status") is not None
                ),
                None,
            )
            if endpoint_req is not None:
                break
            time.sleep(0.1)
        assert endpoint_req is not None, "the fetch() sub-resource was never captured"
        assert endpoint_req["method"] == "GET"
        assert endpoint_req["status"] == 200

        # network_get must decode the endpoint's real body off the CDP response.
        # The body is available once loadingFinished fires, which can trail the
        # status by a beat; retry through the transient empty/error window.
        request_id = endpoint_req["requestId"]
        deadline = time.monotonic() + 15.0
        body = ""
        got = None
        while time.monotonic() < deadline:
            got = service.web_network_get(session_id, request_id)
            assert got.ok, got.error
            body = got.data.get("body") or ""
            if _MARKER in body:
                break
            time.sleep(0.1)
        assert got is not None
        # A JSON body is text, so it is inlined verbatim -- never base64-spilled.
        assert got.data.get("base64_encoded") is False
        assert _MARKER in body, f"network_get did not return the real body: {got.data}"
        recovered = json.loads(body)
        assert recovered["marker"] == _MARKER

        # har_export must render a matching entry from the same capture.
        har = service.web_har_export(session_id)
        assert har.ok, har.error
        assert har.data["entry_count"] >= 1
        har_path = Path(har.data["path"])
        assert har_path.is_file()
        har_text = har_path.read_text(encoding="utf-8")
        assert _ENDPOINT in har_text
    finally:
        service.close_all()
