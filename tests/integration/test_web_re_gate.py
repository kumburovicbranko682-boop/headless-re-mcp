"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import http.server
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

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


def _wait_until(predicate: Callable[[], bool], *, tries: int = 50, delay: float = 0.1) -> bool:
    """CDP events arrive asynchronously; give the wiring a bounded chance to land."""
    for _ in range(tries):
        if predicate():
            return True
        time.sleep(delay)
    return False


def _wait_for_value(
    getter: Callable[[], Any], *, tries: int = 50, delay: float = 0.1
) -> Any:
    for _ in range(tries):
        value = getter()
        if value:
            return value
        time.sleep(delay)
    return getter()


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """Serves an HTML page that pulls one sub-resource carrying a known marker."""

    _INDEX = (
        b"<html><head><title>net-gate</title></head>"
        b'<body><script src="/app.js"></script></body></html>'
    )
    _APP = b"/* NETWORK_GATE_MARKER */ globalThis.__loaded = true;"

    def do_GET(self) -> None:  # noqa: N802 - http.server API name
        cookie: str | None = None
        if self.path in ("/", "/index.html"):
            body, ctype = self._INDEX, "text/html; charset=utf-8"
            # An HttpOnly cookie on the index: document.cookie cannot see it, but
            # CDP's Network.getAllCookies can -- exactly what web.cookies exists to
            # expose. Path/SameSite give the flag fields something real to read.
            cookie = "gate_sid=abc123; Path=/; HttpOnly; SameSite=Lax"
        elif self.path == "/app.js":
            body, ctype = self._APP, "application/javascript"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:  # silence the default stderr access log
        return


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

            # The fixture runs console.log('gate-ready') at parse time. Asserting
            # only web_console(...).ok passes on an empty buffer, so the CDP console
            # wiring (Runtime.consoleAPICalled -> _clip_console_text -> ring) was
            # never actually proven to capture anything. Pin it to the real message.
            def _console_has_marker() -> bool:
                service.web_dom_snapshot(session_id)  # a runner call pumps CDP events
                res = service.web_console(session_id)
                assert res.ok, res.error
                return any(
                    "gate-ready" in (entry.get("text") or "")
                    for entry in res.data["console"]
                )

            assert _wait_until(_console_has_marker), "console.log was not captured over CDP"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_cdp_captures_network_and_reads_a_body() -> None:
    """Network capture is the drift-prone CDP path the data: URL gate never touched.

    A data: URL fires no Network.* events, so requestWillBeSent/responseReceived and
    network_get's Network.getResponseBody were entirely unverified against a real
    browser. Serve a page that pulls a sub-resource with a known marker, then assert
    the request was captured with the status the responseReceived handler filled in
    and that its body reads back through CDP -- something an empty buffer or a broken
    getResponseBody cannot fake.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    service = AnalysisService()
    try:
        url = f"http://127.0.0.1:{port}/index.html"
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

            def _app_entry() -> dict[str, Any] | None:
                service.web_dom_snapshot(session_id)  # a runner call pumps CDP events
                listed = service.web_network_list(session_id, limit=100)
                assert listed.ok, listed.error
                for entry in listed.data["requests"]:
                    url_seen = str(entry.get("url", ""))
                    if url_seen.endswith("/app.js") and entry.get("status"):
                        return entry
                return None

            entry = _wait_for_value(_app_entry)
            assert entry is not None, "sub-resource request was never captured over CDP"
            assert entry["status"] == 200, entry
            assert "javascript" in str(entry.get("mimeType", "")).lower(), entry

            got = service.web_network_get(session_id, entry["requestId"])
            assert got.ok, got.error
            assert "NETWORK_GATE_MARKER" in got.data["body"], got.data
            # Response headers captured at Network.responseReceived: the server
            # sent Content-Type: application/javascript, so a working capture
            # returns it. Lowercase the keys before matching since CDP header
            # name casing is not guaranteed.
            resp_headers = got.data["response_headers"]
            assert isinstance(resp_headers, dict) and resp_headers, got.data
            lowered = {str(k).lower(): str(v) for k, v in resp_headers.items()}
            assert "javascript" in lowered.get("content-type", "").lower(), resp_headers
            # Request headers captured across requestWillBeSent(+ExtraInfo): the
            # browser always sends a User-Agent on a sub-resource fetch, so a
            # working capture returns a non-empty map carrying it.
            req_headers = got.data["request_headers"]
            assert isinstance(req_headers, dict) and req_headers, got.data
            req_lowered = {str(k).lower(): str(v) for k, v in req_headers.items()}
            assert "user-agent" in req_lowered, req_headers
            # The sub-resource is a GET, so has_post_data is False and no
            # request_body is fetched -- pins the flag that gates that fetch.
            assert got.data["has_post_data"] is False, got.data

            # web.cookies reads the browser's cookie store over CDP. The index
            # set an HttpOnly cookie, so a working read returns it with the value
            # and the http_only flag -- and getAllCookies surfacing an HttpOnly
            # cookie is the thing document.cookie could never do, so this proves
            # the CDP path rather than a page-script shortcut.
            def _gate_cookie() -> dict[str, Any] | None:
                res = service.web_cookies(session_id)
                assert res.ok, res.error
                for cookie in res.data["cookies"]:
                    if cookie.get("name") == "gate_sid":
                        return cookie
                return None

            cookie = _wait_for_value(_gate_cookie)
            assert cookie is not None, service.web_cookies(session_id).data
            assert cookie["value"] == "abc123", cookie
            assert cookie["http_only"] is True, cookie
            assert cookie["domain"], cookie
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_js_deobfuscate_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # Prove webcrack actually deobfuscated rather than echoing the input:
        # the fixture hides its secret as the escaped literal "\x48\x33..."
        # ("H3adl3ss"), which never appears decoded in the source. Its presence
        # in the output is something an echo or a broken pass cannot fake, so it
        # pins the gate to a real decode instead of only "some bytes came back".
        assert "H3adl3ss" not in _JS_FIXTURE.read_text(encoding="utf-8")
        assert "H3adl3ss" in code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        # The client creates the output dir before invoking webcrack, and modern
        # webcrack refuses a pre-existing -o directory unless --force is passed.
        # Before that fix this returned backend_error "webcrack unpack failed"
        # having written nothing; the assertions below only hold once webcrack
        # actually wrote its output, so this is the live guard for that fix.
        data = result.data
        assert data["file_count"] >= 1, data
        assert data["count"] >= 1, data
        assert any("deobfuscated" in name for name in data["files"]), data["files"]
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
