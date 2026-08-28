"""Live web network capture gate: real requests through list/get/HAR.

The web gates prove lifecycle honesty (open/close/threads) and page-side
inspection (scripts/console/dom), but no gate ever read the *network* side
against a real browser: ``web.network.list`` is fed by CDP
``Network.requestWillBeSent``/``responseReceived`` events and
``web.network.get`` fetches bodies with a raw ``Network.getResponseBody``
call -- contracts that exist only in unit-test fakes today. If Chromium's
event field names or the body-fetch semantics drift, the fakes stay green
while a live capture lists nothing, exactly the gap shape that let the
webcrack ``-f`` break ship behind a passing deobfuscate gate (and that the
proxy capture gate closes for mitmproxy). Loopback-only: a local origin
serves a page whose script fetches a JSON subresource; no network egress.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_JSON_BODY = b'{"secret": "from-origin"}'
# The page must actually consume the response body: fetch() resolves at the
# headers, and a body nobody reads is never pulled from the network stack, so
# CDP Network.getResponseBody answers "No resource with given identifier"
# (observed live against Chromium 151) and the capture would only be able to
# hand back a body_error.
_PAGE = (
    b"<html><head><title>net-gate</title></head>"
    b"<body><script>fetch('/api/data.json').then(r => r.text());</script></body></html>"
)
_WAIT_S = 20.0


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:  # noqa: BLE001 - any import/launch failure means skip
        return False
    return True


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server contract
        if self.path == "/api/data.json":
            payload, content_type = _JSON_BODY, "application/json"
        else:
            payload, content_type = _PAGE, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        del args


@pytest.fixture()
def origin_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _wait_for_completed_request(service: AnalysisService, session_id: str, url_suffix: str) -> dict:
    """The subresource fetch fires after web.open returns and its status only
    lands once Network.responseReceived arrives, so poll with a deadline for an
    entry that both matches the URL and already carries its status."""
    deadline = time.monotonic() + _WAIT_S
    while time.monotonic() < deadline:
        listed = service.web_network_list(session_id)
        assert listed.ok, listed.error
        for entry in listed.data["requests"]:
            if str(entry.get("url", "")).endswith(url_suffix) and entry.get("status") is not None:
                return dict(entry)
        time.sleep(0.1)
    pytest.fail(f"no completed request for {url_suffix!r} within {_WAIT_S}s")


@pytest.mark.integration
def test_real_page_load_populates_network_list_get_and_har(origin_server: str) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web network Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(origin_server + "/", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            document = _wait_for_completed_request(service, session_id, "/")
            assert document["method"] == "GET"
            assert document["status"] == 200

            fetched = _wait_for_completed_request(service, session_id, "/api/data.json")
            assert fetched["method"] == "GET"
            assert fetched["status"] == 200
            assert "json" in str(fetched["mimeType"]).lower()

            # Body availability lags responseReceived: it needs loadingFinished,
            # which only happens once the page has read the stream. Poll for it.
            deadline = time.monotonic() + _WAIT_S
            while True:
                detail = service.web_network_get(session_id, str(fetched["requestId"]))
                assert detail.ok, detail.error
                if "body_error" not in detail.data:
                    break
                if time.monotonic() >= deadline:
                    pytest.fail(f"response body never became fetchable: {detail.data}")
                time.sleep(0.1)
            # The body must be the origin's actual JSON, inline as text.
            assert detail.data["body"] == _JSON_BODY.decode("ascii")
            assert detail.data["base64_encoded"] is False

            exported = service.web_har_export(session_id)
            assert exported.ok, exported.error
            assert exported.data["entry_count"] >= 2
            har = json.loads(Path(exported.data["path"]).read_text(encoding="utf-8"))
            urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
            assert any(url.endswith("/api/data.json") for url in urls), urls
            statuses = {
                entry["request"]["url"]: entry["response"]["status"]
                for entry in har["log"]["entries"]
            }
            assert statuses[fetched["url"]] == 200
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
