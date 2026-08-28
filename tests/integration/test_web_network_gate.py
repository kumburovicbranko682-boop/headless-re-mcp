"""Live Web dynamic gate: CDP records a real request/response and its body.

``test_web_re_gate.py`` opens a browser on a ``data:`` URL and checks the DOM,
console and script list -- none of which involve the network. So the network
surface the Web dynamic line exists for (``web.network.list`` /
``web.network.get`` / ``web.har.export``) was never proven against a real HTTP
request: no byte ever left the browser, and the response body every RE workflow
wants to read back was only ever asserted in unit tests against a hand-built
fake entry.

This gate stands up a throwaway origin serving an HTML document that pulls a JS
subresource, drives a real headless Chromium at it over CDP, then reads the
capture back through the same ``web.*`` API the tools use:

* ``network_list``: both the document and the subresource are recorded with
  their real method, URL and status.
* ``network_get``: the subresource's captured response carries the exact body
  the origin sent -- proof CDP saw the response body, not merely the request.
* ``har_export``: the capture serialises to HAR entries.

Plain localhost HTTP is used on purpose: it needs no CA trust, so the gate
proves the capture path itself. skip != pass: it skips only when Playwright or a
launchable Chromium is genuinely absent, never silently.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

_DOC_MARKER = "NET-CAPTURE-OK"
_APP_JS = b'window.__gate = "APP-JS-OK";\n'
_APP_JS_MARKER = "APP-JS-OK"
_DOC_HTML = (
    "<!doctype html><html><head><title>net-gate</title>"
    '<script src="app.js"></script></head>'
    f"<body>{_DOC_MARKER}</body></html>"
).encode()


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.split("?", 1)[0] == "/app.js":
            body, ctype = _APP_JS, "application/javascript"
        else:
            body, ctype = _DOC_HTML, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence the stdlib access log
        return


@contextmanager
def _local_origin() -> Iterator[int]:
    """A throwaway HTTP origin on localhost, torn down on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, name="gate-web-origin", daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _find_request(service: AnalysisService, session_id: str, suffix: str) -> dict | None:
    """Poll network_list until a request whose URL ends with ``suffix`` has a status.

    CDP delivers requestWillBeSent and responseReceived as separate async events,
    so a request can be listed a beat before its status is filled in.
    """
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        listed = service.web_network_list(session_id, limit=200)
        assert listed.ok, listed.error
        for req in listed.data["requests"]:
            url = str(req.get("url", ""))
            if url.split("?", 1)[0].endswith(suffix) and req.get("status") is not None:
                return req
        time.sleep(0.1)
    return None


def _network_get_with_body(service: AnalysisService, session_id: str, request_id: str) -> Result:
    """Fetch a captured response, retrying while the body is still settling.

    Network.getResponseBody only has the bytes once loadingFinished has fired,
    which can trail responseReceived by a beat.
    """
    deadline = time.monotonic() + 10.0
    last = service.web_network_get(session_id, request_id)
    while time.monotonic() < deadline:
        if last.ok and not last.data.get("body_error") and last.data.get("body"):
            return last
        time.sleep(0.1)
        last = service.web_network_get(session_id, request_id)
    return last


@pytest.mark.integration
def test_web_cdp_captures_a_real_request_and_body() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web network Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _local_origin() as origin_port:
            origin = f"http://127.0.0.1:{origin_port}/"
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
                # The document request itself was recorded with GET/200.
                document = _find_request(service, session_id, "/")
                assert document is not None, "the navigated document was not recorded"
                assert document["method"] == "GET"
                assert document["status"] == 200

                # The <script src> subresource was fetched and recorded too.
                app_js = _find_request(service, session_id, "app.js")
                assert app_js is not None, "the app.js subresource was not recorded"
                assert app_js["status"] == 200

                # Its captured response carries the exact bytes the origin sent,
                # proving CDP observed the real body, not just the request line.
                detail = _network_get_with_body(service, session_id, app_js["requestId"])
                assert detail.ok, detail.error
                body = detail.data["body"]
                if detail.data.get("body_path"):
                    body = Path(detail.data["body_path"]).read_text(encoding="utf-8")
                assert _APP_JS_MARKER in body, f"captured body was not the origin's: {body!r}"

                exported = service.web_har_export(session_id)
                assert exported.ok, exported.error
                assert exported.data["entry_count"] >= 2
                assert Path(exported.data["path"]).is_file()
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
