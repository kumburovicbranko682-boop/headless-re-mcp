"""Live browser dynamic gate: the read tools return what the page actually did.

``test_web_re_gate`` proves a browser opens and scripts/console/DOM come back;
this drives a real multi-resource page through the rest of the surface a caller
relies on -- the network list, a response body fetched by request id, a script's
source fetched by script id, a screenshot on disk, a HAR export, and a
navigation that changes the URL. Those paths (``Network.getResponseBody`` /
``Debugger.getScriptSource`` over CDP, the artifact spill, HAR assembly) had no
live coverage, so a CDP contract drift would have looked like an empty page.

Deterministic: a stdlib HTTP origin, no external network. Ids are used before
navigating, because a reload retires the pre-navigation request/script ids by
design. skip != pass when Playwright or its browser is unavailable.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_INDEX = (
    b"<html><head><title>dynamic-gate</title>"
    b"<script src='/app.js'></script></head>"
    b"<body>page one</body></html>"
)
_APP_JS = b"console.log('app loaded'); window.__gate = 1234;"
_PAGE_TWO = b"<html><head><title>page-two</title></head><body>page two</body></html>"

_ROUTES = {
    "/index.html": ("text/html", _INDEX),
    "/app.js": ("application/javascript", _APP_JS),
    "/two.html": ("text/html", _PAGE_TWO),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        route = _ROUTES.get(self.path)
        if route is None:
            self.send_error(404)
            return
        content_type, body = route
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def origin() -> Iterator[str]:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = int(httpd.server_address[1])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        thread.join(timeout=5.0)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _poll(
    fetch: Callable[[], Any], done: Callable[[Any], bool], *, deadline_s: float = 10.0
) -> Any:
    """CDP events land on the driver thread a beat after goto returns; poll, don't guess."""
    value = fetch()
    deadline = time.monotonic() + deadline_s
    while not done(value) and time.monotonic() < deadline:
        time.sleep(0.1)
        value = fetch()
    return value


@pytest.mark.integration
def test_web_reads_network_body_script_source_screenshot_and_har(
    origin: str, tmp_path: Path
) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic Gate not run (skip != pass)")
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        created = service.create_session(f"{origin}/index.html", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:

            def list_requests() -> list[dict[str, Any]]:
                listed = service.web_network_list(session_id)
                assert listed.ok, listed.error
                return list(listed.data["requests"])

            requests = _poll(
                list_requests,
                lambda reqs: (
                    {"index.html", "app.js"} <= {str(r["url"]).rsplit("/", 1)[-1] for r in reqs}
                ),
            )
            urls = {str(r["url"]).rsplit("/", 1)[-1] for r in requests}
            assert {"index.html", "app.js"} <= urls, urls

            # A response body fetched by request id must come back intact.
            app_req = next(r for r in requests if str(r["url"]).endswith("/app.js"))
            body = service.web_network_get(session_id, str(app_req["requestId"]))
            assert body.ok, body.error
            assert body.data.get("body_error") is None
            assert "window.__gate" in str(body.data.get("body"))

            # A script's source fetched by script id must match what was served.
            def find_app_script() -> dict[str, Any] | None:
                scripts = service.web_scripts(session_id)
                assert scripts.ok, scripts.error
                return next(
                    (s for s in scripts.data["scripts"] if str(s.get("url")).endswith("/app.js")),
                    None,
                )

            app_script = _poll(find_app_script, lambda found: found is not None)
            assert app_script is not None, "app.js was never reported as a parsed script"
            source = service.web_script_source(session_id, str(app_script["scriptId"]))
            assert source.ok, source.error
            assert "window.__gate" in str(source.data.get("source"))

            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            assert Path(shot.data["path"]).is_file()
            assert int(shot.data["size"]) > 0

            har = service.web_har_export(session_id)
            assert har.ok, har.error
            assert Path(har.data["path"]).is_file()
            assert int(har.data["entry_count"]) >= 1

            # Navigation changes the reported URL (ids above were used first,
            # because a reload retires pre-navigation request/script ids).
            moved = service.web_navigate(session_id, f"{origin}/two.html")
            assert moved.ok, moved.error
            assert moved.data["url"].endswith("/two.html")
            assert "page-two" in moved.data["title"]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
