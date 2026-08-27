"""Live browser dynamic gate: the read tools return what the page actually did.

``test_web_re_gate`` proves a browser opens and scripts/console/DOM come back;
this drives a real multi-resource page through the rest of the surface a caller
relies on -- the network list, a response body fetched by request id, a script's
source fetched by script id, a screenshot on disk, a HAR export, and a
navigation that changes the URL and the DOM snapshot with it. Those paths
(``Network.getResponseBody`` / ``Debugger.getScriptSource`` over CDP, the
artifact spill, HAR assembly, a DOM snapshot that tracks a second document) had
no live coverage, so a CDP contract drift would have looked like an empty page.

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

# A minimal but real WebAssembly module -- header, a () -> i32 type, one
# function exported as "f" returning i32.const 42 -- hand-assembled so the gate
# needs no wat2wasm. A module with actual code is what makes Chromium emit
# ``Debugger.scriptParsed`` with ``scriptLanguage: WebAssembly``; an empty
# (codeless) module may never be reported as a script.
_WASM = bytes.fromhex(
    "0061736d01000000"  # magic + version
    "0105016000017f"  # type section: one () -> i32
    "03020100"  # function section: one func of type 0
    "07050101660000"  # export section: "f" = func 0
    "0a06010400412a0b"  # code section: i32.const 42; end
)
# Instantiated from inline bytes (not fetched) so there is no streaming/network
# race between page load and the module being compiled.
_WASM_PAGE = (
    b"<html><head><title>wasm-gate</title></head><body>wasm host"
    b"<script>WebAssembly.instantiate(Uint8Array.from("
    + str(list(_WASM)).encode()
    + b")).then(r => { window.__w = r.instance.exports.f(); });</script></body></html>"
)

_ROUTES = {
    "/index.html": ("text/html", _INDEX),
    "/app.js": ("application/javascript", _APP_JS),
    "/two.html": ("text/html", _PAGE_TWO),
    "/wasm.html": ("text/html", _WASM_PAGE),
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

            # The DOM snapshot must reflect the live document, not the raw HTML:
            # title and body text come back for page one.
            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert dom.data["title"] == "dynamic-gate"
            assert "page one" in str(dom.data["html"])

            # Navigation changes the reported URL (ids above were used first,
            # because a reload retires pre-navigation request/script ids).
            moved = service.web_navigate(session_id, f"{origin}/two.html")
            assert moved.ok, moved.error
            assert moved.data["url"].endswith("/two.html")
            assert "page-two" in moved.data["title"]

            # ...and the snapshot follows the navigation to the new document.
            dom_two = service.web_dom_snapshot(session_id)
            assert dom_two.ok, dom_two.error
            assert dom_two.data["title"] == "page-two"
            assert "page two" in str(dom_two.data["html"])
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_wasm_list_reports_an_instantiated_module(origin: str, tmp_path: Path) -> None:
    """A WebAssembly module the page compiles must surface in ``web.wasm.list``.

    That list is ``web.scripts`` filtered to ``scriptLanguage == WebAssembly``
    from ``Debugger.scriptParsed``; nothing else exercises the wasm branch live,
    so a break in the language tagging would silently return an empty list while
    JavaScript scripts still came back. The page instantiates a real one-function
    module, so a hit proves Chromium parsed actual wasm, not merely that the
    filter ran.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic Gate not run (skip != pass)")
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        created = service.create_session(f"{origin}/wasm.html", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:

            def wasm_scripts() -> list[dict[str, Any]]:
                listed = service.web_wasm_list(session_id)
                assert listed.ok, listed.error
                return list(listed.data["scripts"])

            scripts = _poll(wasm_scripts, lambda found: bool(found))
            assert scripts, "the instantiated wasm module was never reported as a script"
            assert all(str(s.get("language")).lower() == "webassembly" for s in scripts), scripts
            assert all(str(s.get("scriptId")) for s in scripts), "wasm script missing an id"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
