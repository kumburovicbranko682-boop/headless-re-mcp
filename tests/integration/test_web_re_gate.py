"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

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
def test_js_deobfuscate_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert isinstance(result.data["code"], str)
        assert result.data["bytes"] > 0
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
    # The smallest valid module: magic + version, no sections.
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        assert "module" in result.data["wat"]
    finally:
        service.close_all()
