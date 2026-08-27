"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import base64
import http.server
import socketserver
import threading
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

_PAGE_HTML = (
    b"<html><head><title>gate-net</title>"
    b"<script src='/app.js'></script>"
    b"<script>console.log('inline-ready');</script>"
    b"</head><body>hi</body></html>"
)
_APP_JS = b"globalThis.__loaded = 42; console.log('app-js-ran');\n"

# A hand-assembled, valid WebAssembly module exporting add(i32, i32) -> i32.
# Kept as raw bytes so the gate needs no wat2wasm at run time; the Ubuntu wabt
# package ships wasm2wat/wasm-objdump but not the assembler. Bytes: magic +
# version, a (i32,i32)->i32 type, one function of that type, an "add" export,
# and a body of local.get 0 / local.get 1 / i32.add / end.
_WASM_ADD = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
    ]
)
_WASM_B64 = base64.b64encode(_WASM_ADD).decode("ascii")
_WASM_PAGE_HTML = (
    "<html><head><title>gate-wasm</title><script>"
    f"const b=Uint8Array.from(atob('{_WASM_B64}'),c=>c.charCodeAt(0));"
    "WebAssembly.instantiate(b).then(m=>{"
    "window.__sum=m.instance.exports.add(2,3);console.log('wasm-ready',window.__sum);"
    "}).catch(e=>console.log('wasm-error',''+e));"
    "</script></head><body>wasm</body></html>"
).encode()


class _PageHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:  # keep the test output clean
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/app.js":
            body, ctype = _APP_JS, "application/javascript"
        else:
            body, ctype = _PAGE_HTML, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _WasmPageHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_WASM_PAGE_HTML)))
        self.end_headers()
        self.wfile.write(_WASM_PAGE_HTML)


# Two distinct pages so a navigate can be seen to change what the DOM snapshot
# and status report; each carries a unique title and a unique body marker.
_PAGE_ONE = (
    b"<html><head><title>gate-page-one</title></head>"
    b"<body><div id='marker'>PAGE_ONE_MARKER</div></body></html>"
)
_PAGE_TWO = (
    b"<html><head><title>gate-page-two</title></head>"
    b"<body><div id='marker'>PAGE_TWO_MARKER</div></body></html>"
)


class _TwoPageHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        body = _PAGE_TWO if self.path.rstrip("/") == "/two" else _PAGE_ONE
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_web_cdp_open_and_inspect() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # The page parses an inline script and logs a line during load.
            # Both arrive over CDP events that the recorder buffers, so this
            # asserts capture actually happened, not merely that the read call
            # returned -- a silent stop in recording (a renamed CDP event on a
            # browser bump) would otherwise pass while capturing nothing.
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            assert isinstance(scripts.data["scripts"], list)
            assert scripts.data["count"] >= 1, "no parsed script was captured"

            # consoleAPICalled is dispatched asynchronously on the CDP session,
            # so it can trail domcontentloaded by a moment; poll briefly.
            logged = ""
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                console = service.web_console(session_id)
                assert console.ok, console.error
                logged = " ".join(str(item.get("text", "")) for item in console.data["console"])
                if "gate-ready" in logged:
                    break
                time.sleep(0.1)
            assert "gate-ready" in logged, f"console capture missed the page log: {logged!r}"

            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert "gate" in dom.data["title"]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_navigate_dom_snapshot_and_status_over_http() -> None:
    """Navigate an open session to a second page and see the DOM/status follow.

    web.navigate had only a mocked unit test and web.status none at all, while
    web.dom_snapshot was asserted on title alone -- so page.goto within a live
    session, and the outerHTML the snapshot returns, never ran on a real browser.
    Serve two pages with distinct titles and body markers, open the first, then
    navigate to the second and assert the snapshot's HTML and the status both
    switch from the first page's marker to the second's. A navigate that silently
    stayed put, or a snapshot that returned a stale document, fails here.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web navigate Gate not run (skip != pass)")

    origin = socketserver.TCPServer(("127.0.0.1", 0), _TwoPageHandler)
    port = int(origin.server_address[1])
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    service = AnalysisService()
    try:
        created = service.create_session(f"{base}/", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # First page: the snapshot returns the real outerHTML, not just a
            # title, and status agrees on url and title.
            dom_one = service.web_dom_snapshot(session_id)
            assert dom_one.ok, dom_one.error
            assert dom_one.data["title"] == "gate-page-one"
            assert "PAGE_ONE_MARKER" in dom_one.data["html"]

            status_one = service.web_status(session_id)
            assert status_one.ok, status_one.error
            assert status_one.data["open"] is True
            assert status_one.data["url"].rstrip("/") == base
            assert status_one.data["title"] == "gate-page-one"

            # Navigate to the second page; the result carries the new identity.
            nav = service.web_navigate(session_id, f"{base}/two", timeout=30.0)
            assert nav.ok, nav.error
            assert nav.data["url"].endswith("/two")
            assert nav.data["title"] == "gate-page-two"

            # The snapshot and status must now reflect the second page -- proof
            # the navigation took effect, not a cached first-page document.
            dom_two = service.web_dom_snapshot(session_id)
            assert dom_two.ok, dom_two.error
            assert dom_two.data["title"] == "gate-page-two"
            assert "PAGE_TWO_MARKER" in dom_two.data["html"]
            assert "PAGE_ONE_MARKER" not in dom_two.data["html"]

            status_two = service.web_status(session_id)
            assert status_two.ok, status_two.error
            assert status_two.data["url"].endswith("/two")
            assert status_two.data["title"] == "gate-page-two"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
        origin.shutdown()
        origin.server_close()


@pytest.mark.integration
def test_web_network_capture_and_har_over_http() -> None:
    """Drive the CDP capture surface against a real origin, not a data: URL.

    The other CDP test loads a data: URL, which makes no network requests and
    parses no external script, so network_list / network_get / har_export /
    script_source never run live and a renamed CDP field (Network.* or
    Debugger.getScriptSource, both of which move across Chromium bumps) would
    pass every test while capturing nothing. Serve a page that pulls one
    sub-resource and assert the whole chain records it.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web capture Gate not run (skip != pass)")

    origin = socketserver.TCPServer(("127.0.0.1", 0), _PageHandler)
    port = int(origin.server_address[1])
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"

    service = AnalysisService()
    try:
        created = service.create_session(url, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # The external script is fetched during load; its request and its
            # parse event can trail domcontentloaded, so poll for both.
            app_req: dict[str, object] | None = None
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                listing = service.web_network_list(session_id)
                assert listing.ok, listing.error
                app_req = next(
                    (
                        r
                        for r in listing.data["requests"]
                        if str(r.get("url", "")).endswith("/app.js")
                    ),
                    None,
                )
                if app_req is not None and app_req.get("status") == 200:
                    break
                time.sleep(0.1)
            assert app_req is not None, "the app.js sub-resource request was never captured"
            assert app_req["status"] == 200
            assert "javascript" in str(app_req.get("mimeType", "")).lower()
            assert app_req.get("resourceType") == "Script"

            body = service.web_network_get(session_id, str(app_req["requestId"]))
            assert body.ok, body.error
            assert "globalThis.__loaded" in str(body.data.get("body", ""))

            har = service.web_har_export(session_id)
            assert har.ok, har.error
            assert har.data["entry_count"] >= 2, "HAR did not record the document and its script"

            src_id: str | None = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                scripts = service.web_scripts(session_id)
                assert scripts.ok, scripts.error
                match = next(
                    (
                        s
                        for s in scripts.data["scripts"]
                        if str(s.get("url", "")).endswith("/app.js")
                    ),
                    None,
                )
                if match is not None:
                    src_id = str(match["scriptId"])
                    break
                time.sleep(0.1)
            assert src_id is not None, "the external script's parse event was never captured"
            source = service.web_script_source(session_id, src_id)
            assert source.ok, source.error
            assert "globalThis.__loaded" in str(source.data.get("source", ""))

            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            assert int(shot.data.get("size", 0)) > 0, "screenshot produced no bytes"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
        origin.shutdown()
        origin.server_close()


@pytest.mark.integration
def test_web_captures_an_instantiated_wasm_module() -> None:
    """web.wasm_list must see a real WebAssembly module, not just JS scripts.

    wasm_list filters scriptParsed events for scriptLanguage == "WebAssembly".
    Nothing else drives that path live, so if a Chromium bump renamed the field
    or changed the value, wasm_list would quietly return an empty list and every
    other test would still pass. Instantiate a module in the page and assert it
    is captured, tagged WebAssembly, and addressed under wasm://.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web WASM Gate not run (skip != pass)")

    origin = socketserver.TCPServer(("127.0.0.1", 0), _WasmPageHandler)
    port = int(origin.server_address[1])
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"

    service = AnalysisService()
    try:
        created = service.create_session(url, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # instantiate() resolves after load, and the module's scriptParsed
            # trails it, so poll rather than assume it is already recorded.
            wasm: dict[str, object] | None = None
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                listing = service.web_wasm_list(session_id)
                assert listing.ok, listing.error
                if listing.data["count"] >= 1:
                    wasm = listing.data["scripts"][0]
                    break
                time.sleep(0.15)
            assert wasm is not None, "no WebAssembly module was captured"
            assert str(wasm.get("language", "")).lower() == "webassembly"
            assert str(wasm.get("url", "")).startswith("wasm://")

            # The filter must be a filter: the page also parses JS, so the full
            # script list has to be at least as long as the wasm-only view.
            everything = service.web_scripts(session_id)
            assert everything.ok, everything.error
            assert everything.data["count"] >= listing.data["count"]
            assert any(
                str(s.get("language", "")).lower() == "javascript"
                for s in everything.data["scripts"]
            ), "expected the page's JavaScript to be captured alongside the module"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
        origin.shutdown()
        origin.server_close()


@pytest.mark.integration
def test_js_deobfuscate_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    raw = _JS_FIXTURE.read_text(encoding="utf-8")
    # The secret lives in the fixture only as hex escapes; if the literal string
    # already appeared, decoding it would prove nothing.
    assert "H3adl3ss" not in raw
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # webcrack must have actually transformed the source, not echoed it: the
        # hex-escaped string array decodes to a readable literal, so a no-op pass
        # (or a webcrack that silently failed and returned input) fails here.
        assert "H3adl3ss" in code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_when_webcrack_present() -> None:
    """Unpack drives webcrack -o against a service-owned output dir.

    The client pre-creates that dir, and webcrack 2.x aborts on an existing
    dir unless forced, so this ran green in unit mocks yet failed on every
    real webcrack until the force flag was added. Assert a file lands.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert result.data["file_count"] >= 1, "webcrack produced no output"
        assert result.data["count"] >= 1
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        # The smallest valid module: magic + version, no sections. Proves the
        # tool runs and emits a module wrapper at all.
        empty = tmp_path / "empty.wasm"
        empty.write_bytes(b"\x00asm\x01\x00\x00\x00")
        result = service.wasm_wat(str(empty))
        assert result.ok, result.error
        assert "module" in result.data["wat"]

        # A module with a real function and export must disassemble to WAT that
        # names them -- an empty module never exercises wasm2wat's section
        # decoding, so a decode regression would slip past the smoke case.
        module = tmp_path / "add.wasm"
        module.write_bytes(_WASM_ADD)
        add = service.wasm_wat(str(module))
        assert add.ok, add.error
        wat = add.data["wat"]
        assert "func" in wat
        assert 'export "add"' in wat
        assert "i32.add" in wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    """wasm.info drives wasm-objdump -h -x, a different wabt tool than wasm2wat.

    wasm_wat covers wasm2wat; the objdump path (its own flags and section-header
    output) never ran live. Point it at the add module and assert the section
    dump lists the real Type/Function/Export/Code sections and the exported
    name, so a wabt bump that moved objdump's flags or output fails here.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_ADD)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        dump = result.data["objdump"]
        for section in ("Type", "Function", "Export", "Code"):
            assert section in dump, f"wasm-objdump omitted the {section} section"
        assert '"add"' in dump
    finally:
        service.close_all()
