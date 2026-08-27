"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_BUNDLE_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "webpack_bundle.js"
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "sample_module.wasm"

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


# Markers the capture gate looks for, kept distinct so a body/source mix-up
# would fail rather than pass on the wrong payload.
_APP_JS_MARKER = "app-js-source-marker-42"
_API_BODY_MARKER = "api-response-body-marker"

_SITE_HTML = (
    b"<!doctype html><html><head><title>capture gate</title>"
    b'<script src="/app.js"></script></head><body><h1>hi</h1>'
    b"<script>fetch('/api/data.json').then(r => r.json())"
    b".then(d => console.log('fetched', d.value));</script>"
    b"</body></html>"
)
_SITE_APP_JS = (
    "window.__appLoaded = true;\n"
    f"function helper() {{ return '{_APP_JS_MARKER}'; }}\n"
    "console.log('app.js ran', helper());\n"
).encode()
_SITE_API_JSON = f'{{"value": 123, "marker": "{_API_BODY_MARKER}"}}'.encode()


@contextlib.contextmanager
def _serve_local_site() -> Iterator[str]:
    """A throwaway localhost site with an external script and a JSON endpoint.

    A data: URL cannot load an external script or issue a fetch, so driving the
    real network/script capture paths needs a same-origin server. Ephemeral
    port, daemon thread, torn down on exit.
    """
    routes = {
        "/": ("text/html", _SITE_HTML),
        "/app.js": ("application/javascript", _SITE_APP_JS),
        "/api/data.json": ("application/json", _SITE_API_JSON),
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:  # keep pytest output clean
            del args

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            match = routes.get(self.path.split("?", 1)[0])
            if match is None:
                self.send_response(404)
                self.end_headers()
                return
            content_type, body = match
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


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
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            assert isinstance(scripts.data["scripts"], list)

            console = service.web_console(session_id)
            assert console.ok, console.error

            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert "gate" in dom.data["title"]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_cdp_captures_network_body_script_source_and_screenshot() -> None:
    """Drive the capture surface the DOM-only smoke never reaches.

    network_get, script_source, screenshot and har_export had no gate at all,
    because the smoke test uses a data: URL that loads no external script and
    issues no request. Serve a real same-origin site and assert the fetch's
    response body, the external script's source, a PNG and a HAR all come back
    with the expected bytes.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web capture gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _serve_local_site() as url:
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
                # The external script parses before DOMContentLoaded, but the
                # inline fetch is async, so wait for both CDP events to settle
                # rather than sleeping a fixed amount.
                def _ready() -> bool:
                    listing = service.web_network_list(session_id, limit=200)
                    scripts = service.web_scripts(session_id, limit=200)
                    if not (listing.ok and scripts.ok):
                        return False
                    api_done = any(
                        "data.json" in str(r["url"]) and r.get("status") == 200
                        for r in listing.data["requests"]
                    )
                    app_seen = any(
                        "app.js" in str(s.get("url")) for s in scripts.data["scripts"]
                    )
                    return api_done and app_seen

                assert _wait_until(_ready), "network/script capture never settled"

                listing = service.web_network_list(session_id, limit=200)
                assert listing.ok, listing.error
                api = next(r for r in listing.data["requests"] if "data.json" in str(r["url"]))
                body = service.web_network_get(session_id, api["requestId"])
                assert body.ok, body.error
                assert _API_BODY_MARKER in body.data["body"]

                scripts = service.web_scripts(session_id, limit=200)
                assert scripts.ok, scripts.error
                app = next(s for s in scripts.data["scripts"] if "app.js" in str(s.get("url")))
                source = service.web_script_source(session_id, app["scriptId"])
                assert source.ok, source.error
                assert _APP_JS_MARKER in source.data["source"]

                shot = service.web_screenshot(session_id)
                assert shot.ok, shot.error
                assert shot.data["size"] > 0

                har = service.web_har_export(session_id)
                assert har.ok, har.error
                assert har.data["entry_count"] >= 1
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()


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
def test_js_unpack_bundle_splits_a_webpack_bundle_when_webcrack_present() -> None:
    """webcrack extracts the fixture's modules into separate files.

    Distinct from deobfuscate: this drives the unpack path that writes a tree
    and pages the listing. It also guards a real defect -- the client created
    the output dir and webcrack aborts on an existing one without -f, so every
    unpack failed until that flag was added, and only a live webcrack catches
    it (the unit tests mock the run).
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — bundle unpack gate not run (skip != pass)")
    assert _BUNDLE_FIXTURE.is_file(), f"fixture missing: {_BUNDLE_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_BUNDLE_FIXTURE))
        assert result.ok, result.error
        # A 3-module webpack bundle splits into at least a couple of files.
        assert result.data["file_count"] >= 2, result.data
        assert any(str(name).endswith(".js") for name in result.data["files"]), result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_disassembles_a_real_module_when_wabt_present() -> None:
    """wasm2wat lifts the fixture's exported functions back to WAT.

    An empty (magic + version) module only proves the tool runs; the committed
    fixture has real type/function/export/code sections, so a regression that
    dropped section decoding would fail here instead of passing on an empty
    module.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_WASM_FIXTURE))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "module" in wat
        assert '"add"' in wat
        assert "i32.add" in wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_reports_sections_when_wabt_present() -> None:
    """wasm-objdump enumerates the fixture's sections and exported names."""
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_info(str(_WASM_FIXTURE))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert "Export" in objdump
        assert "Code" in objdump
        assert "add" in objdump
    finally:
        service.close_all()
