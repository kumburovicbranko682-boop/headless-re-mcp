"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

# A page that pulls one external script and fetches one JSON document, so the
# CDP capture has a real subresource and a real response body to retrieve —
# not just the top document a data: URL would give.
_LOCAL_APP_JS = b"window.__probe = function () { return 42; };\nconsole.log('app-loaded');\n"
_LOCAL_DATA_JSON = b'{"marker":"webre-gate","n":123}'
_LOCAL_POST_BODY = '{"user":"alice","token":"s3cr3t"}'
_LOCAL_PAGE = (
    b"<!doctype html><html><head><title>gate-local</title>"
    b'<script src="/app.js"></script>'
    b"<script>fetch('/data.json').then(r=>r.json()).then(j=>console.log('got',j.marker));"
    b"fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},"
    b"body:JSON.stringify({user:'alice',token:'s3cr3t'})}).then(r=>r.text());</script>"
    b"</head><body>hello</body></html>"
)


@contextmanager
def _local_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # keep the gate output quiet
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path.startswith("/app.js"):
                body, ctype = _LOCAL_APP_JS, "application/javascript"
            elif self.path.startswith("/data.json"):
                body, ctype = _LOCAL_DATA_JSON, "application/json"
            else:
                body, ctype = _LOCAL_PAGE, "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            reply = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _poll(predicate: Callable[[], Any], *, timeout: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout
    found = predicate()
    while not found and time.monotonic() < deadline:
        time.sleep(0.1)
        found = predicate()
    return found


# A page that compiles and instantiates a minimal WebAssembly module (magic +
# version, base64 "AGFzbQEAAAA="). Only the browser is needed -- no wabt -- and
# Chromium reports it over CDP as a wasm:// script.
_WASM_PAGE = (
    b"<!doctype html><html><head><title>wasm-gate</title><script>"
    b"const bytes = Uint8Array.from(atob('AGFzbQEAAAA='), c => c.charCodeAt(0));"
    b"WebAssembly.instantiate(bytes).then(() => console.log('wasm-ready'));"
    b"</script></head><body>wasm</body></html>"
)


@contextmanager
def _wasm_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_WASM_PAGE)))
            self.end_headers()
            self.wfile.write(_WASM_PAGE)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)

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
def test_web_cdp_captures_network_and_script_source() -> None:
    """The core Web RE loop: capture a subresource body and a script's source.

    The data-URL gate only proves scripts/console/dom exist. This drives a real
    request against a local server and asserts the two capabilities that carry
    the actual bytes an analyst needs -- network_get returning the exact
    response body, and script_source returning real script text -- both of
    which spill to registered artifacts. Neither had live coverage before.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP capture Gate not run (skip != pass)")
    with _local_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=40.0)
            if not opened.ok:
                pytest.skip(
                    f"chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )

            def _app_script() -> dict[str, Any] | None:
                listing = service.web_scripts(session_id)
                assert listing.ok, listing.error
                for script in listing.data["scripts"]:
                    if str(script.get("url", "")).endswith("/app.js"):
                        return script
                return None

            script = _poll(_app_script)
            assert script is not None, "the /app.js script was never reported over CDP"
            source = service.web_script_source(session_id, script["scriptId"])
            assert source.ok, source.error
            assert source.data["bytes"] > 0
            assert "__probe" in source.data["source"]

            def _data_request() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                for request in listing.data["requests"]:
                    if str(request.get("url", "")).endswith("/data.json"):
                        return request
                return None

            request = _poll(_data_request)
            assert request is not None, "the /data.json request was never captured"
            body = service.web_network_get(session_id, request["requestId"])
            assert body.ok, body.error
            assert body.data["body"] == _LOCAL_DATA_JSON.decode("utf-8")

            # The POST payload the page sent is what an API reverser is after;
            # assert network_get hands back the request body, not just responses.
            def _login_request() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                for candidate in listing.data["requests"]:
                    if str(candidate.get("url", "")).endswith("/api/login"):
                        return candidate
                return None

            login = _poll(_login_request)
            assert login is not None, "the POST /api/login request was never captured"
            posted = service.web_network_get(session_id, login["requestId"])
            assert posted.ok, posted.error
            assert posted.data["method"] == "POST"
            assert posted.data.get("request_body") == _LOCAL_POST_BODY
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_cdp_lists_a_wasm_module_in_the_page() -> None:
    """Finding WebAssembly in a page is a core Web RE step with no live coverage.

    Drive a page that compiles a real wasm module and assert web.wasm.list finds
    it, reports language WebAssembly and a wasm:// url, and that the wasm_only
    filter actually narrows the full script list (a JS script is present too).
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web WASM list Gate not run (skip != pass)")
    with _wasm_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=40.0)
            if not opened.ok:
                pytest.skip(
                    f"chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )

            def _wasm_listing() -> dict[str, Any] | None:
                listing = service.web_wasm_list(session_id)
                assert listing.ok, listing.error
                return listing.data if listing.data["total"] >= 1 else None

            listing = _poll(_wasm_listing)
            assert listing is not None, "no WebAssembly script was ever reported over CDP"
            wasm_script = listing["scripts"][0]
            assert str(wasm_script.get("language")).lower() == "webassembly"
            assert str(wasm_script.get("url", "")).startswith("wasm://")

            # wasm_only must be a real filter: the page also has a JS script, so
            # the full listing is strictly larger than the wasm-only one.
            everything = service.web_scripts(session_id)
            assert everything.ok, everything.error
            assert everything.data["total"] > listing["total"]
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
def test_js_unpack_bundle_when_webcrack_present() -> None:
    """webcrack unpack used to fail every time on webcrack 2.x.

    The client pre-created the -o directory that webcrack insists on owning, so
    the tool exited 1 with "output directory already exists" and the service
    reported backend_error. Only js.deobfuscate was gated, so this end-to-end
    break went unseen. Drive the real tool and assert it actually produces a
    listing (and, pointedly, is not the old backend_error).
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        assert isinstance(result.data["files"], list)
        assert result.data["files"], "webcrack wrote no files"
        assert "output_dir" in result.data
        # A second call takes a fresh unpack dir; it must succeed too, proving
        # the fix is not a one-shot that wedges on the leftover directory.
        again = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert again.ok, again.error
        assert again.data["output_dir"] != result.data["output_dir"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        assert isinstance(result.data["objdump"], str)
        assert "file format wasm" in result.data["objdump"]
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
