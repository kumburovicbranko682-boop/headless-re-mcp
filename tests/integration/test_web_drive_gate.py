"""Web dynamic driving gate: multi-page navigation and live-page WASM listing.

The other Web dynamic gate (``test_web_dynamic_gate.py``) opens one page and
inspects it passively (network / console / DOM / screenshot / HAR). Two
operator-driving capabilities had no live coverage at all:

* ``web.navigate`` -- steer an open session to a second page and confirm the
  page state actually changed, not just that the call returned ok.
* ``web.wasm.list`` -- surface the WebAssembly modules a live page instantiated.
  This filters CDP ``Debugger.scriptParsed`` events to ``scriptLanguage ==
  "WebAssembly"``; nothing had ever driven a real page that compiles a module,
  so the WASM-in-the-browser path was only ever mocked.

The origin is a throwaway local HTTP server (plain HTTP to 127.0.0.1, no CA, no
external network). It serves a page that ``instantiateStreaming``s a real 41-byte
module (an exported ``add``; source in ``_WASM_WAT`` below) and a second page to
navigate to. Runs the service layer, so CDP wiring and the script table are
exercised end to end. Skips honestly when Playwright or a launchable Chromium is
absent -- skip != pass.
"""

from __future__ import annotations

import base64
import contextlib
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# (module (func (export "add") (param i32 i32) (result i32)
#   local.get 0 local.get 1 i32.add))
# Assembled with `wat2wasm add.wat`; 41 bytes. Embedded so the browser test does
# not depend on wabt being installed -- it exercises Chromium's WASM handling,
# not the assembler's.
_WASM_WAT = "(module (func (export \"add\") (param i32 i32) (result i32) i32.add))"
_WASM_B64 = "AGFzbQEAAAABBwFgAn9/AX8DAgEABwcBA2FkZAAACgkBBwAgACABags="
_WASM_BYTES = base64.b64decode(_WASM_B64)

_PAGE2_MARKER = "HEADLESS_RE_WEB_PAGE2_MARKER"
_WASM_LOG = "wasm-add"  # the page logs "wasm-add <sum>" after add(2,3)

_WASM_PAGE = (
    "<html><head><title>wasm-page</title>"
    "<script>"
    "WebAssembly.instantiateStreaming(fetch('/mod.wasm'))"
    ".then(function(r){window.__sum=r.instance.exports.add(2,3);"
    f"console.log('{_WASM_LOG}', window.__sum);}})"
    ".catch(function(e){console.log('wasm-err', String(e));});"
    "</script></head><body><h1>wasm here</h1></body></html>"
).encode()
_PAGE2 = (
    "<html><head><title>second-page</title></head>"
    f"<body><h1>{_PAGE2_MARKER}</h1></body></html>"
).encode()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        if self.path == "/mod.wasm":
            body, content_type = _WASM_BYTES, "application/wasm"
        elif self.path == "/page2":
            body, content_type = _PAGE2, "text/html"
        else:
            body, content_type = _WASM_PAGE, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silence the default stderr access log during the gate."""


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


@dataclass
class _Server:
    service: AnalysisService
    port: int

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


@pytest.fixture(scope="module")
def _server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Server]:
    if not _browser_available():
        pytest.skip("playwright not installed — Web Drive Gate not run (skip != pass)")

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    artifact_root = tmp_path_factory.mktemp("web-drive-artifacts")
    previous = os.environ.get("HEADLESS_RE_ARTIFACT_ROOT")
    os.environ["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    service = AnalysisService(settings=Settings.load())
    try:
        yield _Server(service=service, port=server.server_address[1])
    finally:
        service.close_all()
        server.shutdown()
        thread.join(timeout=5.0)
        if previous is None:
            os.environ.pop("HEADLESS_RE_ARTIFACT_ROOT", None)
        else:
            os.environ["HEADLESS_RE_ARTIFACT_ROOT"] = previous


@contextlib.contextmanager
def _session_on(server: _Server, path: str) -> Iterator[str]:
    """Open a fresh browser session at ``path`` and close it afterwards.

    Per-test sessions keep navigation in one test from perturbing another.
    """
    url = server.url(path)
    session_id = server.service.create_session(url, target="web").data["session"]["id"]
    opened = server.service.web_open(session_id, url=url, headless=True, timeout=30.0)
    if not opened.ok:
        server.service.web_close(session_id)
        pytest.skip(
            "chromium could not launch "
            f"({opened.error.code if opened.error else 'unknown'}) — "
            "Web Drive Gate not run (skip != pass)"
        )
    try:
        yield session_id
    finally:
        server.service.web_close(session_id)


@pytest.mark.integration
def test_navigate_drives_the_session_to_a_second_page(_server: _Server) -> None:
    with _session_on(_server, "/") as session_id:
        # Starts on the wasm page; confirm that, then drive to the second page.
        before = _server.service.web_dom_snapshot(session_id)
        assert before.ok, before.error
        assert before.data["title"] == "wasm-page"

        nav = _server.service.web_navigate(session_id, _server.url("/page2"), timeout=30.0)
        assert nav.ok, nav.error
        assert str(nav.data["url"]).endswith("/page2")
        assert nav.data["title"] == "second-page"

        # The live DOM must reflect the new page, not the one we opened.
        after = _server.service.web_dom_snapshot(session_id)
        assert after.ok, after.error
        assert after.data["title"] == "second-page"
        assert _PAGE2_MARKER in after.data["html"]


@pytest.mark.integration
def test_wasm_list_reports_a_module_the_page_instantiated(_server: _Server) -> None:
    with _session_on(_server, "/") as session_id:
        # The module compiles asynchronously after load, so poll the CDP-backed
        # script table until the WebAssembly entry lands.
        deadline = time.monotonic() + 15.0
        entries: list[dict] = []
        while time.monotonic() < deadline:
            result = _server.service.web_wasm_list(session_id, limit=50)
            assert result.ok, result.error
            entries = result.data["scripts"]
            if entries:
                break
            time.sleep(0.1)
        assert entries, "web.wasm.list never reported the instantiated module"

        module = next(
            (e for e in entries if str(e.get("url", "")).endswith("/mod.wasm")), entries[0]
        )
        assert str(module["language"]).lower() == "webassembly", module
        assert str(module["url"]).endswith("/mod.wasm"), module

        # wasm.list is a projection of the script table, so it must not leak the
        # page's ordinary JavaScript into the WebAssembly-only view.
        for entry in entries:
            assert str(entry.get("language", "")).lower() == "webassembly", entry

        # Prove the module did not merely parse but ran: add(2,3) == 5, logged.
        texts = [
            str(c.get("text", ""))
            for c in _server.service.web_console(session_id, limit=200).data["console"]
        ]
        assert any(f"{_WASM_LOG} 5" in t for t in texts), texts
