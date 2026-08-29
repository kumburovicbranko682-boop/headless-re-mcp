"""Live gate for the web capture chain: network, HAR, screenshot, sources, wasm.

test_web_re_gate proves a CDP session opens and inspects a static page; this
gate proves the capture surfaces exist for real traffic. A loopback HTTP
server serves a page whose script fetches JSON and instantiates a WebAssembly
module, so every surface has ground truth to assert against: the fetched body
must round-trip byte for byte, the HAR must name the page/script/fetch
entries, the screenshot must be an actual PNG, the script source must come
back verbatim, and the module must appear in the WebAssembly-only script
listing -- with its exported call observed in the console, so the row
corresponds to code that really ran. Until this gate, none of web.navigate /
network.list / network.get / har.export / screenshot / script.source /
wasm.list had executable coverage. skip != pass: skips only when playwright
or its browser is unavailable.
"""

from __future__ import annotations

import http.server
import json
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# The same hand-encoded module the wabt gate uses: exports "answer" () -> i32
# returning 42. Embedding it gives the page a wasm instantiation with a result
# the console can prove.
_WASM_MODULE = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
        0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,  # type: () -> i32
        0x03, 0x02, 0x01, 0x00,  # function: uses type 0
        # export "answer" (func 0)
        0x07, 0x0A, 0x01, 0x06, 0x61, 0x6E, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00,
        0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,  # code: i32.const 42; end
    ]
)

_APP_JS = (
    "const bytes = new Uint8Array(["
    + ",".join(str(b) for b in _WASM_MODULE)
    + "]);\n"
    "const inst = new WebAssembly.Instance(new WebAssembly.Module(bytes));\n"
    "console.log('wasm-answer:' + inst.exports.answer());\n"
    "fetch('/data.json').then(r => r.json()).then(d => console.log('data:' + d.secret));\n"
    # A fetch the browser cannot complete, so CDP fires Network.loadingFailed:
    # port 1 is an unsafe port Chromium refuses, giving a deterministic
    # net::ERR_ failure the capture must record as a failed request.
    "fetch('http://127.0.0.1:1/unreachable').catch(() => "
    "console.log('fetch-failed'));\n"
    "// capture-gate-script-marker\n"
)

# A second page whose script fetches the module *over the network* (rather than
# embedding it as a byte array the way /app.js does), so the .wasm is a real
# response body web.network.get can retrieve -- the input the capture -> wasm
# handoff needs and the embedded case cannot provide.
_WASM_FETCH_JS = (
    "fetch('/module.wasm').then(r => r.arrayBuffer())"
    ".then(b => WebAssembly.instantiate(b))"
    ".then(m => console.log('wasm-fetch-answer:' + m.instance.exports.answer()));\n"
)

_PAGES: dict[str, tuple[str, bytes]] = {
    "/": (
        "text/html",
        b"<html><head><title>capture-gate</title>"
        b"<script src='/app.js'></script></head><body>hi</body></html>",
    ),
    "/app.js": ("application/javascript", _APP_JS.encode("utf-8")),
    "/data.json": ("application/json", json.dumps({"secret": "net-gate-payload"}).encode()),
    "/page2": ("text/html", b"<html><head><title>second</title></head><body>2</body></html>"),
    "/wasmfetch": (
        "text/html",
        b"<html><head><title>wasmfetch</title>"
        b"<script src='/wasmfetch.js'></script></head><body>wf</body></html>",
    ),
    "/wasmfetch.js": ("application/javascript", _WASM_FETCH_JS.encode("utf-8")),
    "/module.wasm": ("application/wasm", _WASM_MODULE),
    "/landing": (
        "text/html",
        b"<html><head><title>landing</title></head><body>arrived</body></html>",
    ),
}

# A server-side 302: navigating here lands on /landing. CDP reuses one requestId
# across the hop, so this is the ground truth for the redirect-preservation path.
_REDIRECTS: dict[str, str] = {"/redirect": "/landing"}


class _SiteHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        target = _REDIRECTS.get(self.path)
        if target is not None:
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        mime, body = _PAGES.get(self.path, ("text/plain", b"not found"))
        self.send_response(200 if self.path in _PAGES else 404)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep the test output clean
        return


@pytest.fixture()
def site() -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


def _poll(check: Any, *, timeout: float = 15.0, message: str) -> Any:
    """Return check()'s first truthy value; capture events arrive asynchronously."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = check()
        if found:
            return found
        time.sleep(0.2)
    pytest.fail(message)


@pytest.mark.integration
def test_web_capture_chain_records_real_traffic(site: str) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — web capture Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(site + "/", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # network.list must record the fetch the page's script made,
            # complete with the response metadata CDP attaches later. Wait for
            # the row to be complete: loadingFinished (which stamps the receive
            # phase) arrives moments after responseReceived sets the status, and
            # the timing assertions below read this snapshot and the HAR
            # exported after it.
            def find_fetch_row() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id)
                assert listing.ok, listing.error
                for row in listing.data["requests"]:
                    if row.get("url", "").endswith("/data.json") and row.get("status") == 200:
                        timings = row.get("timings") or {}
                        if timings.get("receive", -1) >= 0:
                            return dict(row)
                return None

            row = _poll(find_fetch_row, message="the page's /data.json fetch was never recorded")
            assert row["method"] == "GET"
            assert row["mimeType"] == "application/json"
            # resourceType is the CDP request kind the summary carries and
            # har.export turns into Chrome's _resourceType hint. The page reaches
            # /data.json with fetch(), so the row must be tagged as a fetch rather
            # than left blank. Allow XHR too: older Chromium labels the same call
            # that way, and the point is that the kind was captured at all.
            assert row["resourceType"] in {"Fetch", "XHR"}

            # network.get must round-trip the body the server actually sent.
            body = service.web_network_get(session_id, row["requestId"])
            assert body.ok, body.error
            assert json.loads(body.data["body"]) == {"secret": "net-gate-payload"}
            assert body.data["base64_encoded"] is False
            assert body.data["body_truncated"] is False

            # har.export must write a document naming every captured exchange.
            exported = service.web_har_export(session_id)
            assert exported.ok, exported.error
            assert exported.data["entry_count"] >= 3
            har_path = Path(exported.data["path"])
            assert exported.data["size"] == har_path.stat().st_size
            document = json.loads(har_path.read_text(encoding="utf-8"))
            entries = document["log"]["entries"]
            har_urls = {entry["request"]["url"] for entry in entries}
            assert {site + "/", site + "/app.js", site + "/data.json"} <= har_urls
            # The browser capture tags each entry with Chrome's _resourceType
            # extension -- the hint separating a document from a script from a
            # fetch, and the only reason har_entry emits a browser-only field the
            # proxy export never sets. Pin that it survives to the HAR for the
            # three request kinds this page makes; a capture that stopped
            # recording the type would still satisfy the url assertion above.
            by_url = {entry["request"]["url"]: entry for entry in entries}
            assert by_url[site + "/"]["_resourceType"] == "Document"
            assert by_url[site + "/app.js"]["_resourceType"] == "Script"
            assert by_url[site + "/data.json"]["_resourceType"] in {"Fetch", "XHR"}

            # startedDateTime must be the real time CDP reported (requestWillBeSent's
            # wallTime), kept on the row as started_at -- not the single export
            # instant that made every entry look simultaneous. The fetch row was
            # captured seconds ago, so its epoch is recent, and the HAR stamp for
            # that URL must equal iso_from_epoch(started_at). This catches a
            # regression that dropped the real time on a real browser, where the
            # unit guard's synthetic wallTime cannot reach.
            started_at = row.get("started_at")
            assert isinstance(started_at, (int, float)) and started_at > 0, row
            assert 0 <= (datetime.now(UTC).timestamp() - started_at) < 3600, started_at
            expected = datetime.fromtimestamp(started_at, UTC).isoformat()
            assert by_url[site + "/data.json"]["startedDateTime"] == expected

            # Real per-phase timings, derived the way Chrome's own HAR export
            # does: send/wait from CDP's response.timing and receive from
            # loadingFinished against the headers-received anchor. The fetch row
            # must carry measured wait and receive durations (ms), and they must
            # thread through to the HAR entry's timings with time equal to the
            # non-negative sum. Measured against real Chromium, where a
            # synthetic ResourceTiming cannot reach; a regression that dropped
            # the timing object or the finished hook would revert entries to
            # time 0 / all -1 and fail here.
            row_timings = row.get("timings")
            assert isinstance(row_timings, dict), row
            assert row_timings.get("wait", -1) >= 0, row_timings
            assert row_timings.get("receive", -1) >= 0, row_timings
            assert all(value >= 0 for value in row_timings.values()), row_timings
            har_timings = by_url[site + "/data.json"]["timings"]
            assert har_timings["send"] == row_timings.get("send", -1)
            assert har_timings["wait"] == row_timings["wait"]
            assert har_timings["receive"] == row_timings["receive"]
            measured = [v for v in har_timings.values() if v >= 0]
            assert by_url[site + "/data.json"]["time"] == round(sum(measured), 3)

            # A request the browser could not complete must be recorded as a
            # failed row (CDP's loadingFailed), not left indistinguishable from
            # one still in flight -- the same observability the proxy gives an
            # errored flow. The page fetches an unsafe port, so a net::ERR_ row
            # for that URL must appear carrying error=true and a null status.
            def find_failed_row() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id)
                assert listing.ok, listing.error
                for row in listing.data["requests"]:
                    if row.get("url", "").startswith("http://127.0.0.1:1/") and row.get("error"):
                        return dict(row)
                return None

            failed = _poll(
                find_failed_row, message="the unreachable fetch was never recorded as failed"
            )
            assert failed["error"] is True
            assert isinstance(failed["error_msg"], str) and failed["error_msg"].startswith(
                "net::ERR_"
            ), failed
            assert failed["status"] is None, failed

            # The failure must survive into the exported artifact, not just the
            # live listing: a re-export now (the earlier one predated the failed
            # fetch) must carry the failed URL as an _error entry -- DevTools'
            # own extension -- with the null status HAR renders as 0, so an
            # analyst opening the HAR still sees which request failed and why.
            reexport = service.web_har_export(session_id)
            assert reexport.ok, reexport.error
            failed_har = json.loads(Path(reexport.data["path"]).read_text(encoding="utf-8"))
            failed_entries = {
                e["request"]["url"]: e for e in failed_har["log"]["entries"]
            }
            failed_entry = failed_entries.get(failed["url"])
            assert failed_entry is not None, failed_entries.keys()
            assert failed_entry["_error"] == failed["error_msg"], failed_entry
            assert failed_entry["response"]["status"] == 0, failed_entry

            # screenshot must be a real PNG, not merely a file that exists.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            image = Path(shot.data["path"]).read_bytes()
            assert image[:8] == b"\x89PNG\r\n\x1a\n"
            assert shot.data["size"] == len(image)

            # script.source must hand back the code the server served.
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            app_rows = [
                s for s in scripts.data["scripts"] if s.get("url", "").endswith("/app.js")
            ]
            assert app_rows, f"/app.js never appeared in scripts: {scripts.data['scripts']}"
            source = service.web_script_source(session_id, app_rows[0]["scriptId"])
            assert source.ok, source.error
            assert "capture-gate-script-marker" in source.data["source"]

            # wasm.list must surface the instantiated module...
            def find_wasm_row() -> dict[str, Any] | None:
                listing = service.web_wasm_list(session_id)
                assert listing.ok, listing.error
                rows = listing.data["scripts"]
                return dict(rows[0]) if rows else None

            wasm_row = _poll(
                find_wasm_row, message="the instantiated wasm module never appeared"
            )
            assert wasm_row["language"] == "WebAssembly"

            # script.source on that WASM script must flag it, not answer a silent
            # empty string. Debugger.getScriptSource returns a WebAssembly module
            # with an empty scriptSource and the bytes in a separate `bytecode`
            # field, so an agent that treated the empty source as "no code" would
            # dead-end; is_wasm plus a note pointing at web.network.get ->
            # wasm.wat/info is the only signal the emptiness is by nature. The JS
            # script.source below proves the populated side; this proves the WASM
            # side, and it exists only because a real browser fills `bytecode`
            # where the unit guard has to mock it -- a Chromium that returned WAT
            # text here instead (so is_wasm never tripped) would fail this.
            wasm_source = service.web_script_source(session_id, wasm_row["scriptId"])
            assert wasm_source.ok, wasm_source.error
            assert wasm_source.data.get("is_wasm") is True, wasm_source.data
            assert wasm_source.data["source"] == "", wasm_source.data
            assert "web.network.get" in wasm_source.data.get("note", ""), wasm_source.data

            # ...and the console proves that module really executed: 42 is
            # computed inside the wasm export, not in JS.
            console = service.web_console(session_id)
            assert console.ok, console.error
            texts = [entry.get("text", "") for entry in console.data["console"]]
            assert any("wasm-answer:42" in text for text in texts), texts

            # navigate must actually move the page and report where it landed.
            moved = service.web_navigate(session_id, site + "/page2")
            assert moved.ok, moved.error
            assert moved.data["url"] == site + "/page2"
            assert moved.data["status"] == 200
            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert dom.data["title"] == "second"
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_network_captured_wasm_body_feeds_wasm_wat(site: str) -> None:
    """A network-fetched .wasm body round-trips through network.get into wasm.wat.

    The is_wasm note on web.script.source, and the service_jsre docstring, both
    tell an agent the same thing: a WebAssembly module has no text source, so
    fetch its response body with web.network.get and analyse the saved .wasm
    with wasm.wat / wasm.info. Nothing proved that handoff actually connects.
    The capture gate above embeds its module in JS, so there is no network body
    to fetch; the wasm gate in test_web_re_gate runs wasm.wat on a standalone
    fixture. This joins the two backends on real infrastructure: a page fetches
    a genuine .wasm over the wire, network.get spills the decoded bytes to
    body_path, and wasm.wat/info decode that very file.

    It guards the exact regression network.get's own comment warns about --
    spilling the base64 *text* into body_path instead of the bytes, which the
    old code did and which would make wasm.wat choke on non-wasm input. So the
    body_path must open with the WebAssembly magic and wasm.wat must recover the
    export and instruction from two different sections. Needs both playwright
    and wabt; skips honestly (skip != pass) when either is absent.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — capture→wasm Gate not run (skip != pass)")
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — capture→wasm Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(site + "/wasmfetch", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            def find_wasm_request() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id)
                assert listing.ok, listing.error
                for row in listing.data["requests"]:
                    if row.get("url", "").endswith("/module.wasm") and row.get("status") == 200:
                        return dict(row)
                return None

            row = _poll(
                find_wasm_request, message="the page's /module.wasm fetch was never recorded"
            )
            assert row["mimeType"] == "application/wasm"

            # network.get must hand back the decoded module, not the base64 text.
            # A wasm body is binary, so CDP returns it base64-encoded and
            # network.get spills the *decoded* bytes to body_path -- inlining
            # nothing. body_path opening with the four-byte WebAssembly magic is
            # what proves the bytes, not the base64, reached the file.
            body = service.web_network_get(session_id, row["requestId"])
            assert body.ok, body.error
            assert body.data["base64_encoded"] is True, body.data
            wasm_path = body.data["body_path"]
            raw = Path(wasm_path).read_bytes()
            assert raw[:4] == b"\x00asm", f"body_path is not raw wasm: {raw[:16]!r}"

            # The captured file feeds wasm.wat directly -- the documented handoff.
            # The export name and the instruction come from two different
            # sections, so together they prove wabt decoded the captured module
            # rather than echoing a header.
            wat = service.wasm_wat(wasm_path)
            assert wat.ok, wat.error
            assert "answer" in wat.data["wat"], wat.data["wat"][:200]
            assert "i32.const 42" in wat.data["wat"], wat.data["wat"][:200]

            # wasm.info reads the same captured file through the other wabt tool.
            # Assert the export *name*, not just the "Export" section header:
            # objdump prints that header for any module with an export section,
            # so naming "answer" is what proves the captured module's export
            # table decoded -- the same bar the standalone wasm_info gate holds.
            info = service.wasm_info(wasm_path)
            assert info.ok, info.error
            objdump = info.data["objdump"]
            assert "Export" in objdump, objdump[:200]
            assert "answer" in objdump, objdump[:200]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_capture_records_a_redirect_hop(site: str) -> None:
    """A real server-side 302 must survive as its own row and reach the HAR.

    CDP reuses one requestId across a redirect chain, so the capture has to
    preserve each hop before the landing request overwrites it. The unit guards
    drive synthetic requestWillBeSent events; this proves the preservation holds
    against real Chromium following a genuine 302, where the redirectResponse
    shape and event ordering are the browser's, not a fake's. skip != pass:
    skips only when playwright or its browser is unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — redirect Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(site + "/redirect", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # The landing document must arrive first (proves navigation followed
            # the 302), then the preserved 302 hop must be findable in the list.
            def find_redirect_hop() -> dict[str, Any] | None:
                listing = service.web_network_list(session_id)
                assert listing.ok, listing.error
                for row in listing.data["requests"]:
                    if row.get("url", "").endswith("/redirect") and row.get("redirect"):
                        return dict(row)
                return None

            hop = _poll(
                find_redirect_hop, message="the 302 redirect hop was never recorded"
            )
            assert hop["status"] == 302, hop
            assert hop["redirect"] is True, hop
            assert hop["redirect_url"].endswith("/landing"), hop
            # Its id is synthetic (the real requestId belongs to the landing
            # hop), so it is distinct from the landing row's id.
            assert hop["requestId"].split(":redirect:")[0] != hop["requestId"], hop

            # The landing hop is its own row with a real 200 and the reused id.
            listing = service.web_network_list(session_id)
            landing = [
                r for r in listing.data["requests"] if r.get("url", "").endswith("/landing")
            ]
            assert landing, listing.data["requests"]
            assert landing[0].get("status") == 200, landing[0]
            assert "redirect" not in landing[0], landing[0]

            # network.get on the synthetic hop id is self-consistent: it resolves
            # the row, and CDP has no body for a redirect, so it degrades to the
            # documented empty-body/body_error shape rather than erroring out or
            # returning the landing page's body.
            got = service.web_network_get(session_id, hop["requestId"])
            assert got.ok, got.error
            assert got.data["body"] == "", got.data
            assert "body_error" in got.data, got.data

            # The 302 must reach the HAR with its Location in response.redirectURL
            # so a viewer draws the chain; the landing entry keeps the empty
            # string a non-redirect response carries.
            exported = service.web_har_export(session_id)
            assert exported.ok, exported.error
            document = json.loads(Path(exported.data["path"]).read_text(encoding="utf-8"))
            by_url = {e["request"]["url"]: e for e in document["log"]["entries"]}
            redirect_entry = by_url.get(site + "/redirect")
            assert redirect_entry is not None, by_url.keys()
            assert redirect_entry["response"]["status"] == 302, redirect_entry
            assert redirect_entry["response"]["redirectURL"].endswith("/landing"), redirect_entry
            assert by_url[site + "/landing"]["response"]["redirectURL"] == ""
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
