"""Web dynamic CDP gate: prove the browser backend really *drives* a page.

The existing Web RE gate opens a ``data:`` URL and checks that the page title
is readable -- enough to prove Chromium launched, not that the CDP wiring works.
This gate stands up a throwaway local HTTP origin (127.0.0.1, ephemeral port) so
every DevTools surface can be checked against real traffic:

* ``web.open``        -- navigation returns HTTP 200 and the served ``<title>``.
* ``web.navigate``    -- a second same-origin page swaps the live DOM/title, and
                         a 404 navigation surfaces its status instead of passing.
* ``web.dom_snapshot``-- the live DOM carries a body marker, not just the title.
* ``web.console``     -- an inline ``console.log`` is captured over CDP.
* ``web.network``     -- the document *and* an external script are recorded with
                         their status/mime, and the script body is fetchable.
* ``web.scripts`` /
  ``web.script_source``-- the external script is parsed and its source retrievable.
* ``web.network.get`` -- a *binary* subresource returns base64-flagged and spills
                         its exact bytes, never a lossy text decode.
* ``web.wasm_list``   -- a live-instantiated WebAssembly module is enumerated
                         (and shown to have actually executed), and ``wasm_only``
                         is proven to be a real filter, not a passthrough.
* ``web.screenshot``  -- a non-empty PNG is written and registered.
* ``web.har_export``  -- the captured flows serialize to a HAR that references
                         them *and* carries every mandatory HAR 1.2 member, so a
                         strict consumer (DevTools import, har-validator) loads it.
* ``artifacts.*``     -- the screenshot and HAR register as artifacts and read
                         back, byte-for-byte, through list/describe/read -- the
                         loop an unattended agent uses to fetch what it captured.

Everything is local, so the only external dependency is Playwright + a Chromium
build. Each is checked up front and the gate skips loudly ("skip != pass") when
they are absent, rather than passing vacuously.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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

# A distinct same-origin page for web.navigate, plus a path that 404s so the
# 4xx-status-surfacing branch of the backend can be exercised for real.
_PAGE2_TITLE = "gate-page-two"
_PAGE2_MARKER = "GATE_PAGE2_MARKER_7f3a"
_PAGE2_HTML = (
    "<!doctype html><html><head><meta charset=utf-8>"
    f"<title>{_PAGE2_TITLE}</title></head>"
    f"<body><p id=two>{_PAGE2_MARKER}</p></body></html>"
)
_MISSING_HTML = "<!doctype html><html><body>not found</body></html>"


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
            status, body, ctype = 200, _APP_JS.encode("utf-8"), "application/javascript"
        elif self.path == "/page2":
            status, body, ctype = 200, _PAGE2_HTML.encode("utf-8"), "text/html; charset=utf-8"
        elif self.path == "/missing":
            status, body, ctype = 404, _MISSING_HTML.encode("utf-8"), "text/html; charset=utf-8"
        else:
            status, body, ctype = 200, _INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8"
        self.send_response(status)
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


# Every byte value 0x00..0xFF: not valid UTF-8, so CDP must return the response
# body base64Encoded -- exactly the path a text-only capture never walks. The
# page fetch()es it (rather than <img>, whose body Chromium does not reliably
# buffer for getResponseBody) and logs the received length, so the console also
# proves the browser really pulled all 256 bytes before we read them back.
_BLOB_BYTES = bytes(range(256))
_BLOB_READY = "BLOB_READY"
_BINARY_HTML = (
    "<!doctype html><html><head><meta charset=utf-8>"
    f"<title>{_TITLE}</title>"
    "<script>fetch('/blob.bin').then(r=>r.arrayBuffer())."
    f"then(b=>{{console.log('{_BLOB_READY} '+b.byteLength);}});</script>"
    "</head><body>blob</body></html>"
)


class _BinaryHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - required name
        if self.path == "/blob.bin":
            status, body, ctype = 200, _BLOB_BYTES, "application/octet-stream"
        else:
            status, body, ctype = 200, _BINARY_HTML.encode("utf-8"), "text/html; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
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
        # ...and the live export is spec-complete, not just non-empty: a missing
        # mandatory 1.2 member makes a strict consumer reject the whole file, so
        # prove the artifact an analyst actually opens would load.
        _assert_har_1_2(parsed)


def test_web_dynamic_retrieves_a_binary_response_body(_service: AnalysisService) -> None:
    """A binary response body must come back as bytes, not a lossy text decode.

    CDP flags a non-UTF-8 body ``base64Encoded``; the backend decodes it once and
    spills the *raw* bytes to ``body_path`` rather than inlining the base64 or
    writing replacement characters. The existing coverage only ever fetched a
    text body (app.js), so this walks the other branch: serve every byte value
    0x00..0xFF, pull it as an <img>, and prove the spilled artifact is those exact
    bytes -- the guarantee that a caller never mistakes a decode for the payload.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin(_BinaryHandler) as url:
        session_id = _open_on(_service, url)
        blob_url = url + "blob.bin"

        # The page's fetch() actually pulled all 256 bytes (proven over the
        # console) before we ask CDP for the buffered body.
        def _blob_fetched() -> bool:
            res = _service.web_console(session_id)
            return res.ok and any(
                f"{_BLOB_READY} {len(_BLOB_BYTES)}" in str(e.get("text", ""))
                for e in res.data["console"]
            )

        assert _wait_until(_blob_fetched), "page never fetched the full binary body"

        # The fetch lands as its own flow (responseReceived is async).
        def _blob_flow() -> dict[str, Any] | None:
            res = _service.web_network_list(session_id, limit=200)
            if not res.ok:
                return None
            for r in res.data["requests"]:
                if str(r.get("url", "")) == blob_url:
                    return r
            return None

        assert _wait_until(lambda: _blob_flow() is not None), "binary subresource never captured"
        flow = _blob_flow()
        assert flow is not None

        got = _service.web_network_get(session_id, flow["requestId"])
        assert got.ok, got.error
        # base64-flagged, never inlined as text, and reporting the decoded size.
        assert got.data["base64_encoded"] is True, got.data
        assert got.data["body"] == "", got.data
        assert got.data["body_truncated"] is False, got.data
        assert got.data["body_bytes"] == len(_BLOB_BYTES), got.data

        # The spilled artifact holds the served bytes verbatim -- decode round-trip
        # intact, no replacement characters, no base64 written to the .bin.
        path = got.data.get("body_path")
        assert isinstance(path, str) and path, got.data
        assert Path(path).read_bytes() == _BLOB_BYTES, "spilled bytes are not the bytes served"


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


def test_web_dynamic_navigate_across_pages_and_surfaces_404(_service: AnalysisService) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin() as url:
        session_id = _open_on(_service, url)  # starts on "/"

        # web.navigate swaps the live page: a new URL, title and 200 status.
        nav = _service.web_navigate(session_id, url + "page2")
        assert nav.ok, nav.error
        assert nav.data.get("status") == 200, nav.data
        assert _PAGE2_TITLE in nav.data["title"], nav.data
        assert nav.data["url"].rstrip("/").endswith("/page2"), nav.data

        # ...and the DOM really is the second page, not the first.
        dom = _service.web_dom_snapshot(session_id)
        assert dom.ok, dom.error
        assert _PAGE2_MARKER in dom.data["html"], dom.data["html"][:400]
        assert _DOM_MARKER not in dom.data["html"], "first page's DOM lingered after navigate"

        # A 4xx main document resolves normally; its status must be surfaced so a
        # navigation onto an error page cannot report the same success as a hit.
        missing = _service.web_navigate(session_id, url + "missing")
        assert missing.ok, missing.error
        assert missing.data.get("status") == 404, missing.data


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


def test_web_captures_round_trip_through_the_artifact_store(_service: AnalysisService) -> None:
    """A capture an agent asked for must read back through the artifact tools.

    web.screenshot and web.har_export register what they wrote, because a bare
    path is a dead end on the tool surface: nothing opens one, so an unattended
    agent could not fetch the screenshot or HAR it just captured. Prove the whole
    loop -- the id each returns is listed, describes to the file's real digest,
    and reads back its exact bytes *through artifacts.read* rather than by
    re-opening the path the capture happened to leak.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web dynamic CDP gate not run (skip != pass)")
    with _origin() as url:
        session_id = _open_on(_service, url)

        shot = _service.web_screenshot(session_id, full_page=True)
        assert shot.ok, shot.error
        shot_id = shot.data.get("artifact_id")
        assert isinstance(shot_id, str) and shot_id, shot.data

        har = _service.web_har_export(session_id)
        assert har.ok, har.error
        har_id = har.data.get("artifact_id")
        assert isinstance(har_id, str) and har_id, har.data

        # Both captures are listed against this session with their kind and a
        # non-zero size: the registry, not just the filesystem, knows them.
        listed = _service.artifacts_list(session_id)
        assert listed.ok, listed.error
        by_id = {str(a["id"]): a for a in listed.data["artifacts"]}
        assert shot_id in by_id and har_id in by_id, sorted(by_id)
        assert by_id[shot_id]["kind"] == "web_screenshot", by_id[shot_id]
        assert by_id[har_id]["kind"] == "web_har", by_id[har_id]
        assert by_id[shot_id]["size"] > 0 and by_id[har_id]["size"] > 0, by_id

        # describe carries the same digest the file has on disk -- the registry
        # recorded the real sha256, not a placeholder.
        described = _service.artifacts_describe(shot_id)
        assert described.ok, described.error
        meta = described.data["artifact"]
        on_disk = hashlib.sha256(Path(meta["path"]).read_bytes()).hexdigest()
        assert meta["sha256"] == on_disk, (meta["sha256"], on_disk)
        assert meta["size"] == Path(meta["path"]).stat().st_size, meta

        # Read the PNG *through* artifacts.read (hex-encoded) and confirm the
        # signature: the bytes came back via the tool, not the raw path.
        png = _service.artifacts_read(shot_id, limit=64)
        assert png.ok, png.error
        assert png.data["encoding"] == "hex", png.data
        assert bytes.fromhex(png.data["data"])[:8] == b"\x89PNG\r\n\x1a\n", png.data["data"][:16]
        assert png.data["size"] == meta["size"], png.data

        # The HAR reads back through the same tool and parses to the real log,
        # with at least the document flow this session served -- retrieval, not
        # merely storage.
        har_read = _service.artifacts_read(har_id, limit=200_000)
        assert har_read.ok, har_read.error
        parsed = json.loads(bytes.fromhex(har_read.data["data"]).decode("utf-8"))
        entries = parsed["log"]["entries"]
        assert entries, parsed
        assert any(str(e["request"]["url"]).startswith(url) for e in entries), [
            e["request"]["url"] for e in entries
        ]

        # An id that was never registered is a clean not_found, never a crash
        # through the tool boundary.
        missing = _service.artifacts_describe("deadbeef" * 4)
        assert not missing.ok and missing.error is not None, missing
        assert missing.error.code == "not_found", missing.error


def _assert_har_1_2(parsed: dict[str, Any]) -> None:
    """Every entry carries the HAR 1.2 members a strict consumer requires.

    The shared serializer exists so both the web and proxy exports load in the
    tools an analyst actually opens a HAR in (Chrome DevTools "Import HAR",
    har-validator); those reject the whole file when a mandatory member is
    absent. This checks the *live* export really carries them, not merely that
    the unit-tested serializer can.
    """
    log = parsed["log"]
    assert log.get("version") == "1.2", log.get("version")
    creator = log.get("creator", {})
    assert creator.get("name") and creator.get("version"), creator
    entries = log.get("entries")
    assert entries, parsed
    for entry in entries:
        for key in ("startedDateTime", "time", "request", "response", "cache", "timings"):
            assert key in entry, (key, sorted(entry))
        for key in (
            "method",
            "url",
            "httpVersion",
            "cookies",
            "headers",
            "queryString",
            "headersSize",
            "bodySize",
        ):
            assert key in entry["request"], (key, sorted(entry["request"]))
        for key in (
            "status",
            "statusText",
            "httpVersion",
            "cookies",
            "headers",
            "content",
            "redirectURL",
            "headersSize",
            "bodySize",
        ):
            assert key in entry["response"], (key, sorted(entry["response"]))
        for key in ("size", "mimeType"):
            assert key in entry["response"]["content"], (key, sorted(entry["response"]["content"]))
        for key in ("send", "wait", "receive"):
            assert key in entry["timings"], (key, sorted(entry["timings"]))


def _read_capture(payload: dict[str, Any]) -> str:
    """Read a spilled artifact's text regardless of which key names the path."""
    for key in ("path", "artifact_path", "har_path"):
        value = payload.get(key)
        if isinstance(value, str):
            with open(value, encoding="utf-8") as fh:
                return fh.read()
    raise AssertionError(f"no artifact path in payload: {sorted(payload)}")
