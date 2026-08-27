"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import base64
import json
import socket
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
# A tiny non-text response (PNG magic + a byte run including 0x89/0x1a/0x00) so
# CDP reports it base64Encoded and network.get has to decode it back to bytes.
_LOCAL_PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))
_LOCAL_PAGE = (
    b"<!doctype html><html><head><title>gate-local</title>"
    b'<script src="/app.js"></script>'
    b"<script>fetch('/data.json').then(r=>r.json()).then(j=>console.log('got',j.marker));"
    b"fetch('/logo.png').then(r=>r.arrayBuffer());"
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
            marker = False
            if self.path.startswith("/app.js"):
                body, ctype = _LOCAL_APP_JS, "application/javascript"
            elif self.path.startswith("/data.json"):
                body, ctype = _LOCAL_DATA_JSON, "application/json"
                marker = True
            elif self.path.startswith("/logo.png"):
                body, ctype = _LOCAL_PNG, "image/png"
            else:
                body, ctype = _LOCAL_PAGE, "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            # A distinctive response header the header-capture assertion can find.
            if marker:
                self.send_header("X-Gate-Marker", "webre-gate-header")
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

# A real module exporting add(i32,i32)->i32, so the bytes pulled back out of the
# live page disassemble to something an analyst can read (a func and an export),
# not just a header. Hand-assembled: type, function, export and code sections.
_WASM_ADD_MODULE = (
    b"\x00asm\x01\x00\x00\x00"  # magic + version
    b"\x01\x07\x01\x60\x02\x7f\x7f\x01\x7f"  # type: (i32,i32)->i32
    b"\x03\x02\x01\x00"  # function: one func, type 0
    b"\x07\x07\x01\x03add\x00\x00"  # export "add" = func 0
    b"\x0a\x09\x01\x07\x00\x20\x00\x20\x01\x6a\x0b"  # code: local.get 0/1, i32.add
)
_WASM_ADD_B64 = base64.b64encode(_WASM_ADD_MODULE).decode("ascii")
_WASM_EXTRACT_PAGE = (
    b"<!doctype html><html><head><title>wasm-extract</title><script>"
    b"const bytes = Uint8Array.from(atob('" + _WASM_ADD_B64.encode("ascii") + b"'), "
    b"c => c.charCodeAt(0));"
    b"WebAssembly.instantiate(bytes).then(() => console.log('wasm-ready'));"
    b"</script></head><body>wasm</body></html>"
)


@contextmanager
def _wasm_extract_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_WASM_EXTRACT_PAGE)))
            self.end_headers()
            self.wfile.write(_WASM_EXTRACT_PAGE)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


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
            # Response headers carry the RE-relevant metadata (content type, the
            # custom marker we set); they must come back on network.get, and the
            # list must not carry them.
            resp_headers = {
                str(k).lower(): str(v) for k, v in body.data.get("response_headers", {}).items()
            }
            assert resp_headers.get("x-gate-marker") == "webre-gate-header"
            assert "json" in resp_headers.get("content-type", "")
            assert "response_headers" not in request, "the list row must omit headers"

            # The response size is accrued from dataReceived/loadingFinished,
            # which land after responseReceived, so poll until the flow finished
            # and assert the decoded body size matches the bytes we served.
            def _data_sized() -> dict[str, Any] | None:
                for candidate in service.web_network_list(session_id, limit=1000).data[
                    "requests"
                ]:
                    if str(candidate.get("url", "")).endswith("/data.json") and candidate.get(
                        "response_size"
                    ) is not None:
                        return candidate
                return None

            sized = _poll(_data_sized)
            assert sized is not None, "the /data.json response size was never captured"
            assert sized["response_size"] == len(_LOCAL_DATA_JSON)
            assert sized.get("finished") is True
            assert int(sized.get("transfer_size", 0)) >= len(_LOCAL_DATA_JSON)

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
            # The request the page sent declared a JSON content type; that
            # request header must be captured too.
            req_headers = {
                str(k).lower(): str(v) for k, v in posted.data.get("request_headers", {}).items()
            }
            assert "json" in req_headers.get("content-type", "")

            # A binary response (image/png) comes over CDP as base64 text; the
            # captured body_path must be the decoded PNG bytes, not the base64
            # string -- otherwise saving or re-analysing the resource is broken.
            def _png_request() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                for candidate in listing.data["requests"]:
                    if str(candidate.get("url", "")).endswith("/logo.png"):
                        return candidate
                return None

            png = _poll(_png_request)
            assert png is not None, "the /logo.png request was never captured"
            got = service.web_network_get(session_id, png["requestId"])
            assert got.ok, got.error
            assert got.data["base64_encoded"] is True
            assert got.data["body"] == ""
            assert got.data["body_bytes"] == len(_LOCAL_PNG)
            png_path = got.data.get("body_path")
            assert isinstance(png_path, str), "a binary body must always spill to a file"
            assert Path(png_path).read_bytes() == _LOCAL_PNG
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_cdp_screenshot_and_har_export() -> None:
    """The two evidence-capture tools -- screenshot and HAR -- had no live test.

    Both cross the Playwright boundary in ways unit mocks can't vouch for: the
    screenshot rides page.screenshot() and must land a real PNG file that gets
    registered as a capture, and the HAR must serialise the session's recorded
    requests into a valid HAR 1.2 log containing the page and its subresources.
    A Playwright API drift would silently break either, so pin them here.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web screenshot/HAR Gate not run (skip != pass)")
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

            # Wait for the subresource to finish (size accrued), so the HAR has
            # more than the top document and its content.size is populated.
            def _data_seen() -> bool:
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                return any(
                    str(r.get("url", "")).endswith("/data.json")
                    and r.get("response_size") is not None
                    for r in listing.data["requests"]
                )

            assert _poll(_data_seen), "the /data.json subresource was never captured"

            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            shot_path = Path(shot.data["path"])
            assert shot_path.is_file(), "screenshot reported a path that is not a file"
            raw = shot_path.read_bytes()
            assert raw[:8] == b"\x89PNG\r\n\x1a\n", "screenshot is not a real PNG"
            assert shot.data["size"] == len(raw) > 100
            assert shot.data.get("artifact_id"), "the screenshot was not registered as a capture"

            har = service.web_har_export(session_id)
            assert har.ok, har.error
            assert har.data["entry_count"] >= 2
            log = json.loads(Path(har.data["path"]).read_text(encoding="utf-8"))["log"]
            assert log["version"] == "1.2"
            urls = [entry["request"]["url"] for entry in log["entries"]]
            assert any(u.rstrip("/").endswith(str(url).rstrip("/")) or u == url for u in urls), (
                "the HAR is missing the top document"
            )
            assert any(u.endswith("/data.json") for u in urls), (
                "the HAR is missing the /data.json subresource"
            )
            # The log must be conformant HAR 1.2 (viewers reject entries missing
            # these), and the captured response headers must land in it.
            data_entry = next(
                e for e in log["entries"] if e["request"]["url"].endswith("/data.json")
            )
            for field in ("startedDateTime", "time", "cache", "timings"):
                assert field in data_entry, field
            for field in ("send", "wait", "receive"):
                assert field in data_entry["timings"], field
            for side in ("request", "response"):
                assert isinstance(data_entry[side]["headers"], list)
                assert isinstance(data_entry[side]["cookies"], list)
            resp_headers = {
                str(h["name"]).lower(): str(h["value"])
                for h in data_entry["response"]["headers"]
            }
            assert resp_headers.get("x-gate-marker") == "webre-gate-header", (
                "the HAR did not carry the captured response header"
            )
            # The captured response size must reach HAR content.size, not the
            # old hardcoded 0, so a viewer shows a real payload size.
            assert data_entry["response"]["content"]["size"] == len(_LOCAL_DATA_JSON)
            assert int(data_entry.get("_transferSize", 0)) >= len(_LOCAL_DATA_JSON)
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
def test_web_cdp_extracts_wasm_bytecode_for_offline_analysis() -> None:
    """web.wasm.list found modules but there was no way to get their bytes.

    Chromium returns a Wasm module's bytes in getScriptSource's ``bytecode``
    field (``scriptSource`` is empty for Wasm), which the client used to drop --
    so the live-page-to-wasm.* pipeline was broken end to end. Drive a page with
    a real add() module, pull the bytes back through web.script.source, and
    assert they are byte-identical to what the page instantiated, land in a
    registered .wasm artifact, and (when wabt is present) disassemble to a module
    whose exported function is visible.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web WASM extract Gate not run (skip != pass)")
    with _wasm_extract_site() as url:
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

            def _wasm_script() -> dict[str, Any] | None:
                listing = service.web_wasm_list(session_id)
                assert listing.ok, listing.error
                for script in listing.data["scripts"]:
                    if str(script.get("language", "")).lower() == "webassembly":
                        return script
                return None

            wasm_script = _poll(_wasm_script)
            assert wasm_script is not None, "no WebAssembly script was reported over CDP"

            source = service.web_script_source(session_id, wasm_script["scriptId"])
            assert source.ok, source.error
            data = source.data
            assert data.get("is_wasm") is True, "the wasm module was not recognised"
            assert data["wasm_bytes"] == len(_WASM_ADD_MODULE)
            assert data.get("artifact_id"), "the wasm module was not registered as a capture"
            wasm_path = Path(data["wasm_path"])
            assert wasm_path.is_file()
            raw = wasm_path.read_bytes()
            assert raw == _WASM_ADD_MODULE, "the extracted bytes are not the module the page ran"

            # The whole point is offline analysis: feed the pulled bytes to the
            # wasm.* line and confirm it decodes to a readable module.
            if WasmClient().available:
                wat = service.wasm_wat(str(wasm_path))
                assert wat.ok, wat.error
                assert "module" in wat.data["wat"]
                assert "func" in wat.data["wat"]
        finally:
            service.close_all()


_ERROR_PAGE = (
    b"<!doctype html><html><head><title>err-gate</title>"
    b"<script>console.log('before-throw');</script>"
    b"<script>throw new Error('gate-uncaught-boom');</script>"
    b"<script>console.log('after-throw');</script>"
    b"</head><body>x</body></html>"
)


@contextmanager
def _error_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_ERROR_PAGE)))
            self.end_headers()
            self.wfile.write(_ERROR_PAGE)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_web_cdp_captures_uncaught_exceptions() -> None:
    """Uncaught page errors were dropped -- web.console only saw console.* calls.

    An unhandled exception (and its stack) is frequently the single most useful
    line on a page under analysis, and it never arrives via consoleAPICalled.
    Drive a page that throws at top level and assert web.console surfaces it as
    an error entry tagged source exception, while ordinary console.log around it
    still comes through.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web exception Gate not run (skip != pass)")
    with _error_site() as url:
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

            def _exception_entry() -> dict[str, Any] | None:
                console = service.web_console(session_id, limit=200)
                assert console.ok, console.error
                for entry in console.data["console"]:
                    if entry.get("source") == "exception":
                        return entry
                return None

            entry = _poll(_exception_entry)
            assert entry is not None, "the uncaught exception was never captured"
            assert entry["type"] == "error"
            assert "gate-uncaught-boom" in str(entry["text"])
            # The stack site pins the throw to the page's own script, not just
            # the message text: url points back at the served page, line is the
            # 1-based location Chromium reports.
            assert "127.0.0.1" in str(entry.get("url", "")), entry
            assert isinstance(entry.get("line"), int) and entry["line"] >= 1, entry

            texts = [
                str(e.get("text", ""))
                for e in service.web_console(session_id, limit=200).data["console"]
            ]
            assert any("before-throw" in t for t in texts), "ordinary console.log was lost"
        finally:
            service.close_all()


@contextmanager
def _blocked_request_site() -> Iterator[str]:
    # Reserve a loopback port and leave it bound but never listening: a connect
    # to it is refused at the network layer, so the page can trigger a
    # deterministic loadingFailed (ERR_CONNECTION_REFUSED) with no flaky DNS or
    # timeout. Holding the socket open also keeps the port from being reused.
    dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    page = (
        b"<!doctype html><html><head><title>blocked-gate</title><script>"
        b"fetch('http://127.0.0.1:" + str(dead_port).encode("ascii") + b"/api/blocked')"
        b".catch(e => console.log('fetch-failed', e && e.message));"
        b"</script></head><body>x</body></html>"
    )

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        dead.close()


@pytest.mark.integration
def test_web_cdp_flags_a_blocked_request() -> None:
    """A request the browser fails to fetch was left indistinguishable from pending.

    Only responseReceived was wired, so a blocked/aborted request (CORS, CSP,
    net::ERR_*, cancellation) sat at status None forever with its failure reason
    dropped -- a false negative for anyone hunting a blocked telemetry endpoint
    or a failing API call. Drive a page whose fetch is refused at the network
    layer and assert the request comes back flagged failed with error_text and
    no phantom status.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web failed-request Gate not run (skip != pass)")
    with _blocked_request_site() as url:
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

            def _failed_request() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                for request in listing.data["requests"]:
                    if str(request.get("url", "")).endswith("/api/blocked") and request.get(
                        "failed"
                    ):
                        return request
                return None

            request = _poll(_failed_request, timeout=15.0)
            assert request is not None, "the refused request was never flagged failed"
            assert request["failed"] is True
            assert request.get("status") is None
            assert isinstance(request.get("error_text"), str)
            assert request["error_text"], "the failure reason was dropped"
        finally:
            service.close_all()


_COOKIE_PAGE = (
    b"<!doctype html><html><head><title>cookie-gate</title></head>"
    b"<body>cookies</body></html>"
)


@contextmanager
def _cookie_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # An HttpOnly session cookie (the token an analyst hunts) plus an
            # ordinary one. Secure is omitted: Chromium rejects Secure cookies
            # over plain http, and this origin is http.
            self.send_header(
                "Set-Cookie", "sid=s3cr3t-token; Path=/; HttpOnly; SameSite=Lax"
            )
            self.send_header("Set-Cookie", "theme=dark; Path=/")
            self.send_header("Content-Length", str(len(_COOKIE_PAGE)))
            self.end_headers()
            self.wfile.write(_COOKIE_PAGE)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_web_cdp_reads_the_cookie_jar() -> None:
    """web had no way to read cookies -- the auth/session state itself.

    A page's Set-Cookie response is where the session token lives, and it never
    appears in the DOM or console. Drive a page that sets an HttpOnly session
    cookie and assert web.cookies surfaces it with its value and the HttpOnly
    flag, so the jar an analyst needs is actually reachable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web cookie Gate not run (skip != pass)")
    with _cookie_site() as url:
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

            def _sid_cookie() -> dict[str, Any] | None:
                jar = service.web_cookies(session_id)
                assert jar.ok, jar.error
                for cookie in jar.data["cookies"]:
                    if cookie.get("name") == "sid":
                        return cookie
                return None

            sid = _poll(_sid_cookie, timeout=15.0)
            assert sid is not None, "the session cookie was never read back"
            assert sid["value"] == "s3cr3t-token"
            assert sid["http_only"] is True
            assert sid.get("same_site") == "Lax"

            names = {c.get("name") for c in service.web_cookies(session_id).data["cookies"]}
            assert "theme" in names, "an ordinary cookie was lost"
        finally:
            service.close_all()


_STORAGE_PAGE = (
    b"<!doctype html><html><head><title>storage-gate</title><script>"
    b"try{"
    b"localStorage.setItem('access_token','eyJhbGciOiJIUzI1NiJ9.payload');"
    b"localStorage.setItem('theme','dark');"
    b"sessionStorage.setItem('csrf','csrf-9182');"
    b"}catch(e){}"
    b"</script></head><body>storage</body></html>"
)


@contextmanager
def _storage_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_STORAGE_PAGE)))
            self.end_headers()
            self.wfile.write(_STORAGE_PAGE)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_web_cdp_reads_web_storage() -> None:
    """Cookies were reachable but Web Storage was not -- where SPAs keep tokens.

    localStorage/sessionStorage hold JWTs, refresh tokens and app state that
    never appear in the cookie jar or the DOM. Drive a page that writes both
    stores and assert web.storage reads them back keyed, valued, and split into
    the two areas, with the origin surfaced.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web storage Gate not run (skip != pass)")
    with _storage_site() as url:
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

            def _has_token() -> dict[str, Any] | None:
                res = service.web_storage(session_id)
                assert res.ok, res.error
                for item in res.data["local"]["items"]:
                    if item.get("key") == "access_token":
                        return res.data
                return None

            data = _poll(_has_token, timeout=15.0)
            assert data is not None, "the localStorage token was never read back"
            local = {item["key"]: item["value"] for item in data["local"]["items"]}
            assert local["access_token"] == "eyJhbGciOiJIUzI1NiJ9.payload"
            assert local["theme"] == "dark"
            session = {item["key"]: item["value"] for item in data["session"]["items"]}
            assert session["csrf"] == "csrf-9182", "sessionStorage was lost"
            assert str(data["origin"]).startswith("http://127.0.0.1")
        finally:
            service.close_all()


_BIG_DOM_MARKER = b"gate-big-dom-marker"
# A body well past the 200 KB inline cap so the snapshot has to spill.
_BIG_DOM_PAGE = (
    b"<!doctype html><html><head><title>big-dom-gate</title></head><body>"
    + (b"<div class='row'>" + _BIG_DOM_MARKER + b"</div>") * 12000
    + b"</body></html>"
)


@contextmanager
def _big_dom_site() -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_BIG_DOM_PAGE)))
            self.end_headers()
            self.wfile.write(_BIG_DOM_PAGE)

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_web_cdp_dom_snapshot_spills_a_large_document() -> None:
    """A large DOM was sliced to 200 KB in the browser and the rest lost.

    A real SPA's markup runs past that, so the snapshot -- often the whole
    point of the capture -- came back cut with no way to reach the full page.
    Drive a page whose DOM is ~500 KB and assert web.dom.snapshot spills the
    complete document to html_path (byte length in bytes), the inline html is
    only a bounded preview, and the spilled file holds the whole thing.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web DOM spill Gate not run (skip != pass)")
    with _big_dom_site() as url:
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

            snap = service.web_dom_snapshot(session_id)
            assert snap.ok, snap.error
            data = snap.data
            assert data["truncated"] is True, "a 500 KB DOM should not fit inline"
            assert "html_path" in data, data
            assert data["bytes"] > 200_000
            assert len(str(data["html"]).encode("utf-8")) <= data["bytes"]
            spilled = Path(data["html_path"])
            assert spilled.is_file()
            full = spilled.read_bytes()
            assert len(full) == data["bytes"]
            assert _BIG_DOM_MARKER in full
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
