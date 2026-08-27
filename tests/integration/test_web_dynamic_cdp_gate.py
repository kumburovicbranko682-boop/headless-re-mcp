"""Web dynamic CDP gate: prove the browser backend really *drives* a page.

The existing Web RE gate opens a ``data:`` URL and checks that the page title
is readable -- enough to prove Chromium launched, not that the CDP wiring works.
This gate stands up a throwaway local HTTP origin (127.0.0.1, ephemeral port) so
every DevTools surface can be checked against real traffic:

* ``web.open``        -- navigation returns HTTP 200 and the served ``<title>``.
* ``web.dom_snapshot``-- the live DOM carries a body marker, not just the title.
* ``web.console``     -- an inline ``console.log`` is captured over CDP.
* ``web.network``     -- the document *and* an external script are recorded with
                         their status/mime, and the script body is fetchable.
* ``web.scripts`` /
  ``web.script_source``-- the external script is parsed and its source retrievable.
* ``web.wasm_list``   -- a live-instantiated WebAssembly module is enumerated
                         (and shown to have actually executed), and ``wasm_only``
                         is proven to be a real filter, not a passthrough.
* ``web.screenshot``  -- a non-empty PNG is written and registered.
* ``web.har_export``  -- the captured flows serialize to a HAR referencing them.

Everything is local, so the only external dependency is Playwright + a Chromium
build. Each is checked up front and the gate skips loudly ("skip != pass") when
they are absent, rather than passing vacuously.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

pytestmark = pytest.mark.integration

# Unique markers so the assertions cannot be satisfied by chrome chrome or a
# stray same-origin resource -- only by the bytes this gate served.
_TITLE = "gate-dynamic"
_DOM_MARKER = "GATE_DOM_MARKER_7f3a"
_CONSOLE_MARKER = "GATE_CONSOLE_MARKER_7f3a"
_SCRIPT_MARKER = "GATE_SCRIPT_MARKER_7f3a"

_APP_JS = f"// {_SCRIPT_MARKER}\nfunction gateFn() {{ return 42; }}\nconsole.log(gateFn());\n"

_INDEX_HTML = (
    "<!doctype html><html><head><meta charset=utf-8>"
    f"<title>{_TITLE}</title>"
    f"<script>console.log('{_CONSOLE_MARKER}');window.__gate=1;</script>"
    '<script src="/app.js"></script>'
    f"</head><body><div id=gate>{_DOM_MARKER}</div></body></html>"
)


# Canonical minimal add.wasm -- (func (param i32 i32) (result i32) -> a + b),
# base64-embedded so the page instantiates it with no extra fetch. The page logs
# the computed sum, so the console proves the module actually *ran*; CDP reports
# the compiled module as a WebAssembly script for web.wasm_list to enumerate.
_WASM_SUM = 42  # add(19, 23)
_WASM_READY = "WASM_READY"
_WASM_ADD_B64 = base64.b64encode(
    bytes(
        (
            0x00,
            0x61,
            0x73,
            0x6D,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
            0x07,
            0x01,
            0x60,
            0x02,
            0x7F,
            0x7F,
            0x01,
            0x7F,
            0x03,
            0x02,
            0x01,
            0x00,
            0x07,
            0x07,
            0x01,
            0x03,
            0x61,
            0x64,
            0x64,
            0x00,
            0x00,
            0x0A,
            0x09,
            0x01,
            0x07,
            0x00,
            0x20,
            0x00,
            0x20,
            0x01,
            0x6A,
            0x0B,
        )
    )
).decode()
_WASM_INSTANTIATE = (
    f"const b=Uint8Array.from(atob('{_WASM_ADD_B64}'),c=>c.charCodeAt(0));"
    "WebAssembly.instantiate(b).then("
    f"r=>{{console.log('{_WASM_READY} '+r.instance.exports.add(19,23));}});"
)
_WASM_HTML = (
    f"<!doctype html><html><head><meta charset=utf-8><title>{_TITLE}</title>"
    f"<script>{_WASM_INSTANTIATE}</script></head><body>wasm</body></html>"
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence stderr spam
        pass

    def do_GET(self) -> None:  # noqa: N802 - required name
        if self.path == "/app.js":
            body = _APP_JS.encode("utf-8")
            ctype = "application/javascript; charset=utf-8"
        else:
            body = _INDEX_HTML.encode("utf-8")
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _WasmHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - required name
        body = _WASM_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _origin(handler: type[BaseHTTPRequestHandler] = _Handler) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[0], server.server_address[1]
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 8.0) -> bool:
    """Poll a CDP-fed buffer until it settles.

    Console/script/network events arrive asynchronously after ``web.open``
    returns (goto only waits for ``domcontentloaded``), so a single read can
    race the event that proves the point. Re-read until it lands or time runs
    out -- a returned ``False`` becomes a real assertion failure at the call
    site, never a silent pass.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


@pytest.fixture
def _service() -> Iterator[AnalysisService]:
    service = AnalysisService()
    try:
        yield service
    finally:
        service.close_all()


def _open_on(service: AnalysisService, url: str) -> str:
    created = service.create_session(url, target="web")
    assert created.ok, created.error
    session_id: str = created.data["session"]["id"]
    opened = service.web_open(session_id, headless=True, timeout=45.0)
    if not opened.ok:
        pytest.skip(
            "chromium could not launch (browser build not installed?): "
            f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
        )
    assert opened.data["opened"] is True
    assert opened.data.get("status") == 200, opened.data
    assert _TITLE in opened.data["title"], opened.data
    return session_id


def test_web_dynamic_dom_console_and_scripts(_service: AnalysisService) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin() as url:
        session_id = _open_on(_service, url)

        # The live DOM, not just the <title>: the body marker only exists in the
        # document the origin served, so finding it proves a real snapshot.
        dom = _service.web_dom_snapshot(session_id)
        assert dom.ok, dom.error
        assert _TITLE in dom.data["title"]
        assert _DOM_MARKER in dom.data["html"], dom.data["html"][:400]

        # console.log fired during page load and reached us over CDP.
        def _console_has_marker() -> bool:
            res = _service.web_console(session_id)
            return res.ok and any(
                _CONSOLE_MARKER in str(e.get("text", "")) for e in res.data["console"]
            )

        assert _wait_until(_console_has_marker), "console marker never captured over CDP"

        # The external <script src="/app.js"> was parsed; its source is fetchable
        # and carries the marker only the origin's app.js contained.
        def _app_script() -> dict[str, Any] | None:
            res = _service.web_scripts(session_id)
            if not res.ok:
                return None
            for s in res.data["scripts"]:
                if str(s.get("url", "")).endswith("/app.js"):
                    return s
            return None

        assert _wait_until(lambda: _app_script() is not None), "app.js was never parsed"
        script = _app_script()
        assert script is not None
        source = _service.web_script_source(session_id, script["scriptId"])
        assert source.ok, source.error
        assert _SCRIPT_MARKER in source.data["source"], source.data


def test_web_dynamic_network_capture_and_har(_service: AnalysisService) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin() as url:
        session_id = _open_on(_service, url)

        # Both the document and the external script must show up as flows with a
        # 200 and their mime types. Poll: responseReceived lands after open().
        def _flows() -> dict[str, dict[str, Any]]:
            res = _service.web_network_list(session_id, limit=200)
            if not res.ok:
                return {}
            return {str(r.get("url", "")): r for r in res.data["requests"]}

        def _both_captured() -> bool:
            flows = _flows()
            doc = flows.get(url)
            app = flows.get(url + "app.js")
            return bool(doc and app and doc.get("status") == 200 and app.get("status") == 200)

        assert _wait_until(_both_captured), f"document + app.js not both captured: {list(_flows())}"
        flows = _flows()
        assert "html" in str(flows[url].get("mimeType", "")).lower(), flows[url]
        assert "javascript" in str(flows[url + "app.js"].get("mimeType", "")).lower(), flows[
            url + "app.js"
        ]

        # The captured script body is retrievable and is the bytes we served.
        app_id = flows[url + "app.js"]["requestId"]
        body = _service.web_network_get(session_id, app_id)
        assert body.ok, body.error
        assert _SCRIPT_MARKER in body.data["body"], body.data

        # HAR export serializes the captured flows and references app.js.
        har = _service.web_har_export(session_id)
        assert har.ok, har.error
        assert har.data["entry_count"] >= 2, har.data
        har_text = _read_capture(har.data)
        parsed = json.loads(har_text)
        urls = {e["request"]["url"] for e in parsed["log"]["entries"]}
        assert url + "app.js" in urls, sorted(urls)


def test_web_dynamic_enumerates_a_live_wasm_module(_service: AnalysisService) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin(_WasmHandler) as url:
        session_id = _open_on(_service, url)

        # The module actually ran: the page logged add(19, 23) over CDP. This
        # proves execution, not merely that a wasm blob was downloaded/compiled.
        def _wasm_ran() -> bool:
            res = _service.web_console(session_id)
            return res.ok and any(
                f"{_WASM_READY} {_WASM_SUM}" in str(e.get("text", "")) for e in res.data["console"]
            )

        assert _wait_until(_wasm_ran), "wasm module never executed / logged its result"

        # web.wasm_list enumerates the compiled module V8 reported over CDP.
        def _wasm_scripts() -> list[dict[str, Any]]:
            res = _service.web_wasm_list(session_id)
            return list(res.data["scripts"]) if res.ok else []

        assert _wait_until(lambda: len(_wasm_scripts()) >= 1), "no WebAssembly module enumerated"
        modules = _wasm_scripts()
        assert all(str(m.get("language", "")).lower() == "webassembly" for m in modules), modules
        assert any(str(m.get("url", "")).startswith("wasm://") for m in modules), modules

        # wasm_only is a real filter: the unfiltered listing still carries the
        # page's plain-JS script, which the wasm-only view excluded above.
        every = _service.web_scripts(session_id, wasm_only=False)
        assert every.ok, every.error
        langs = {str(s.get("language", "")).lower() for s in every.data["scripts"]}
        assert "javascript" in langs, langs


def test_web_dynamic_screenshot_is_a_real_png(_service: AnalysisService) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin() as url:
        session_id = _open_on(_service, url)
        shot = _service.web_screenshot(session_id, full_page=True)
        assert shot.ok, shot.error
        assert shot.data["size"] > 0, shot.data
        with open(shot.data["path"], "rb") as fh:
            magic = fh.read(8)
        assert magic == b"\x89PNG\r\n\x1a\n", magic


def _read_capture(payload: dict[str, Any]) -> str:
    """Read a spilled artifact's text regardless of which key names the path."""
    for key in ("path", "artifact_path", "har_path"):
        value = payload.get(key)
        if isinstance(value, str):
            with open(value, encoding="utf-8") as fh:
                return fh.read()
    raise AssertionError(f"no artifact path in payload: {sorted(payload)}")
