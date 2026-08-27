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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "add_module.wasm"

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


_SITE_HTML = (
    "<!doctype html><html><head><title>net-gate</title>"
    '<script src="/app.js"></script></head>'
    "<body>hello-net</body></html>"
)
_SITE_JS_MARKER = "net-gate-marker-9449"
_SITE_JS = f"console.log('net-gate-ready'); window.__netgate = '{_SITE_JS_MARKER}';\n"


class _GateHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/app.js":
            body, ctype = _SITE_JS.encode("utf-8"), "application/javascript"
        else:
            body, ctype = _SITE_HTML.encode("utf-8"), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _local_site() -> Iterator[str]:
    """Serve a two-resource page from localhost so CDP capture has real traffic.

    A ``data:`` URL never crosses the network stack, so it cannot prove the
    ``Network.*`` capture path. A tiny loopback server (document + a JS
    subresource that logs to the console) gives the browser genuine requests to
    record without reaching the internet.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


def _poll(fn: Callable[[], Any], predicate: Callable[[Any], bool], *, tries: int = 40) -> Any:
    """Re-run ``fn`` until ``predicate`` holds; CDP telemetry arrives async."""
    result = fn()
    for _ in range(tries):
        if predicate(result):
            return result
        time.sleep(0.25)
        result = fn()
    return result


# A deterministic binary body big enough that its base64 (~4/3 the size) exceeds
# the 200 KB inline cap and therefore spills to a file -- which is where the
# base64-vs-bytes bug lived.
_BLOB_BYTES = bytes((i * 7 + 3) & 0xFF for i in range(300_000))
_BLOB_PATH = "/blob.bin"
_BLOB_HTML = (
    "<!doctype html><html><head><title>blob-gate</title></head><body>blob"
    f"<script>fetch('{_BLOB_PATH}').then(r=>r.arrayBuffer()).then(()=>"
    "{window.__blobdone=1;});</script></body></html>"
)


class _BlobHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _BLOB_PATH:
            body, ctype = _BLOB_BYTES, "application/octet-stream"
        else:
            body, ctype = _BLOB_HTML.encode("utf-8"), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _binary_site() -> Iterator[str]:
    """Serve a page that fetches a binary blob, so CDP records a base64 body."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BlobHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


_WASM_PATH = "/add.wasm"
# The page instantiates a real WASM module so V8 registers a WebAssembly script
# the Debugger domain reports; that is the only way to exercise the live
# module-bytes extraction path in web.script.source.
_WASM_HTML = (
    "<!doctype html><html><head><title>wasm-gate</title></head><body>wasm"
    f"<script>fetch('{_WASM_PATH}').then(r=>r.arrayBuffer())"
    ".then(b=>WebAssembly.instantiate(b)).then(()=>{window.__wasmdone=1;});"
    "</script></body></html>"
)


class _WasmHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:  # silence per-request logging
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == _WASM_PATH:
            body, ctype = _WASM_FIXTURE.read_bytes(), "application/wasm"
        else:
            body, ctype = _WASM_HTML.encode("utf-8"), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _wasm_site() -> Iterator[str]:
    """Serve a page that instantiates a WASM module from loopback."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WasmHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.server_close()


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
def test_web_cdp_captures_network_console_and_screenshot(tmp_path: Path) -> None:
    """Prove the CDP capture surface beyond DOM: network, bodies, console,
    script source, screenshot, HAR.

    ``test_web_cdp_open_and_inspect`` only reaches scripts/console/DOM on a
    ``data:`` URL, which never touches the network stack -- so ``network_list``,
    ``network_get``, ``script_source``, ``screenshot`` and ``har_export`` (the
    reasons the CDP line exists) had no end-to-end coverage. A loopback page
    that pulls a JS subresource and logs to the console gives the browser real
    traffic to record; every reader below is then asserted against that traffic.
    CDP telemetry is delivered asynchronously, so the request/console/script
    reads poll briefly. skip != pass when playwright or chromium is unavailable.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _local_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Network: the /app.js subresource must have been captured, 200.
                listing = _poll(
                    lambda: service.web_network_list(session_id, limit=200),
                    lambda r: r.ok
                    and any(str(x.get("url", "")).endswith("/app.js") for x in r.data["requests"]),
                )
                assert listing.ok, listing.error
                app = [
                    x
                    for x in listing.data["requests"]
                    if str(x.get("url", "")).endswith("/app.js")
                ]
                assert app, listing.data["requests"]
                assert app[0]["status"] == 200, app[0]

                # network_get returns the real response body for that request.
                body = service.web_network_get(session_id, str(app[0]["requestId"]))
                assert body.ok, body.error
                assert _SITE_JS_MARKER in body.data.get("body", ""), body.data

                # Console: the subresource logged a line while the page loaded.
                console = _poll(
                    lambda: service.web_console(session_id),
                    lambda r: r.ok
                    and any("net-gate-ready" in str(e.get("text", "")) for e in r.data["console"]),
                )
                assert console.ok, console.error
                assert any(
                    "net-gate-ready" in str(e.get("text", "")) for e in console.data["console"]
                ), console.data["console"]

                # Scripts + script_source: recover the subresource's JS text.
                scripts = _poll(
                    lambda: service.web_scripts(session_id, limit=200),
                    lambda r: r.ok
                    and any(str(s.get("url", "")).endswith("/app.js") for s in r.data["scripts"]),
                )
                assert scripts.ok, scripts.error
                app_scripts = [
                    s for s in scripts.data["scripts"] if str(s.get("url", "")).endswith("/app.js")
                ]
                assert app_scripts, scripts.data["scripts"]
                source = service.web_script_source(session_id, str(app_scripts[0]["scriptId"]))
                assert source.ok, source.error
                assert _SITE_JS_MARKER in source.data.get("source", ""), source.data

                # Screenshot: a real PNG lands in the session artifact tree.
                shot = service.web_screenshot(session_id)
                assert shot.ok, shot.error
                assert shot.data["size"] > 0, shot.data
                assert Path(shot.data["path"]).is_file(), shot.data

                # HAR: the capture exports with at least the two requests in it.
                har = service.web_har_export(session_id)
                assert har.ok, har.error
                assert har.data["entry_count"] >= 1, har.data
                assert Path(har.data["path"]).is_file(), har.data
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_network_get_spills_a_binary_body_as_real_bytes(tmp_path: Path) -> None:
    """A binary response body must reach disk as the resource, not base64 text.

    CDP returns binary bodies base64-encoded. network_get used to write that
    base64 *text* into the ``.bin`` artifact, so an agent pulling a WASM module,
    image or encrypted blob got a file 4/3 the real size that it still had to
    decode. Fetch a 300 KB binary through the page (its base64 exceeds the inline
    cap, so it spills), then assert base64_encoded is set and the spilled file is
    byte-for-byte the origin's payload -- not its base64. skip != pass without a
    browser.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    with _binary_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Wait for the fetch to be recorded *and* to have a response, so
                # getResponseBody has a body to return.
                listing = _poll(
                    lambda: service.web_network_list(session_id, limit=200),
                    lambda r: r.ok
                    and any(
                        str(x.get("url", "")).endswith(_BLOB_PATH) and x.get("status") == 200
                        for x in r.data["requests"]
                    ),
                )
                assert listing.ok, listing.error
                blob = [
                    x
                    for x in listing.data["requests"]
                    if str(x.get("url", "")).endswith(_BLOB_PATH)
                ]
                assert blob, listing.data["requests"]

                got = service.web_network_get(session_id, str(blob[0]["requestId"]))
                assert got.ok, got.error
                assert got.data.get("base64_encoded") is True, got.data
                spill = got.data.get("body_path")
                assert spill, f"large binary body must spill to disk: {got.data}"
                on_disk = Path(spill).read_bytes()
                # The artifact is the real resource, byte-for-byte -- not base64.
                assert on_disk == _BLOB_BYTES, (len(on_disk), len(_BLOB_BYTES))
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


@pytest.mark.integration
def test_web_script_source_extracts_a_live_wasm_module_for_static_analysis(
    tmp_path: Path,
) -> None:
    """A WASM module seen in a page must come out as a real .wasm the tools accept.

    CDP hands a WebAssembly script back as WAT text plus base64 module bytes;
    only the text used to be kept, so a module could be listed via web.wasm.list
    yet never fed to wasm.wat / wasm.info / ghidra, which all take a .wasm path.
    This instantiates a real module in the page, extracts it through
    web.script.source, and proves the spilled bytes are a genuine module by
    round-tripping them through wasm.wat. skip != pass without a browser.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    if not _WASM_FIXTURE.is_file():
        pytest.skip(f"wasm fixture missing: {_WASM_FIXTURE} — skip != pass")
    with _wasm_site() as url:
        service = AnalysisService()
        try:
            created = service.create_session(url, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # V8 registers the WebAssembly script asynchronously once the
                # module instantiates; poll web.wasm.list until it shows up. A
                # cold browser can take longer than the default window to fetch,
                # compile and instantiate, so allow extra tries here.
                listing = _poll(
                    lambda: service.web_wasm_list(session_id, limit=200),
                    lambda r: r.ok and bool(r.data["scripts"]),
                    tries=80,
                )
                assert listing.ok, listing.error
                wasm_scripts = listing.data["scripts"]
                assert wasm_scripts, "no WebAssembly script was reported by the page"

                source = service.web_script_source(
                    session_id, str(wasm_scripts[0]["scriptId"])
                )
                assert source.ok, source.error
                data = source.data
                assert data.get("language") == "WebAssembly", data
                module_path = data.get("wasm_bytecode_path")
                assert module_path, f"no module bytes extracted: {data}"
                assert data.get("wasm_bytes", 0) > 0, data
                assert data.get("wasm_bytecode_id"), data

                on_disk = Path(module_path).read_bytes()
                # The artifact is a genuine module: the WASM magic, real bytes.
                assert on_disk[:4] == b"\x00asm", on_disk[:8]

                # The registered id resolves to those same bytes.
                read = service.artifacts_read(
                    str(data["wasm_bytecode_id"]), offset=0, limit=4
                )
                assert read.ok and read.data is not None, read.error
                assert read.data["data"].startswith("0061736d"), read.data

                # The whole point: the extracted module round-trips through the
                # static WASM tooling. Only assert the handoff when wabt is present.
                if WasmClient().available:
                    wat = service.wasm_wat(module_path)
                    assert wat.ok, wat.error
                    assert "module" in (wat.data.get("wat") or ""), wat.data
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
def test_js_deobfuscate_spills_full_output_when_truncated(tmp_path: Path) -> None:
    """A large real deobfuscation must remain fully recoverable, not half lost.

    Measured against live webcrack: a ~600 KB minified bundle unminifies past
    900 KB, but the inline reply caps at 400 KB, so most of the code used to be
    unrecoverable. The service now spills the full text to an artifact; this
    proves artifact_path holds every byte and the inline code is just a preview.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    big = tmp_path / "big.min.js"
    big.write_text(
        ";".join(
            f"function f{i}(a,b){{if(a>b){{return a*{i}+b}}else{{return b-a+{i}}}}}"
            for i in range(9000)
        ),
        encoding="utf-8",
    )
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(big))
        assert result.ok, result.error
        data = result.data
        assert data["truncated"] is True, "expected the bundle to overflow inline"
        assert len(data["code"].encode("utf-8")) <= 400_000
        artifact = Path(data["artifact_path"])
        assert artifact.is_file()
        full = artifact.read_bytes()
        assert len(full) == data["artifact_bytes"] == data["bytes"]
        # The artifact is the whole output; the inline code is only its prefix.
        assert len(full) > len(data["code"].encode("utf-8"))
        assert full.decode("utf-8", "ignore").startswith(data["code"][:200])
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_faults_soft_on_unparseable_input(tmp_path: Path) -> None:
    """Broken JS must fault with a structured error, not a false success.

    webcrack reports a parse failure by exiting non-zero and writing the
    SyntaxError to stderr (stdout empty) -- the mirror image of wasm-objdump,
    which put its error on stdout and slipped past the same guard. This pins the
    JS reader's half of that contract: unparseable input comes back
    backend_error (never internal_error, never ok with garbage as "code"), while
    an empty file -- which webcrack accepts -- still succeeds with empty output.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        broken = tmp_path / "broken.js"
        broken.write_text("function ( { syntax ]]] error !!!", encoding="utf-8")
        result = service.js_deobfuscate(str(broken))
        assert not result.ok and result.error is not None
        assert result.error.code == "backend_error", result.error

        binary = tmp_path / "binary.js"
        binary.write_bytes(bytes(range(64)))
        binary_result = service.js_deobfuscate(str(binary))
        assert not binary_result.ok and binary_result.error is not None
        assert binary_result.error.code == "backend_error", binary_result.error

        # An empty module is legal input, not a failure: webcrack exits 0 and the
        # reader must stay on the success path rather than over-rejecting.
        empty = tmp_path / "empty.js"
        empty.write_text("", encoding="utf-8")
        empty_result = service.js_deobfuscate(str(empty))
        assert empty_result.ok, empty_result.error
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        # webcrack owns the output directory: the service pre-creates a unique
        # tree for retention, so unpack has to pass --force or webcrack aborts
        # with "output directory already exists". A green here proves the whole
        # write path, not just deobfuscation to stdout.
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        assert result.data["files"], "webcrack produced no files"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_WASM_FIXTURE))
        assert result.ok, result.error
        wat = result.data["wat"]
        # A real module round-trips to a function definition and its named export,
        # not just the bare "(module" wrapper an empty module would yield.
        assert "(func" in wat
        assert '(export "add"' in wat
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_info(str(_WASM_FIXTURE))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x enumerates the section headers and details; the
        # export table names the "add" function the module deliberately exposes.
        assert "Export" in objdump
        assert "add" in objdump
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_accepts_minimal_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # Boundary case: the smallest valid module is magic + version, no sections.
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        assert "module" in result.data["wat"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_readers_fault_soft_on_a_malformed_module(tmp_path: Path) -> None:
    """A bad .wasm must fault with a structured error, not smuggle it as output.

    wasm2wat writes its error to stderr and empties stdout, but wasm-objdump
    writes the diagnostic to STDOUT and exits non-zero -- so wasm_info used to
    return ok with "error: bad magic value" as the objdump payload, dressing a
    failed inspection up as analysis. Both readers must now come back
    backend_error (never internal_error, never a false success), and the actual
    diagnostic must be reachable so an agent learns why the module was rejected.
    """
    if not WasmClient().available:
        pytest.skip("wabt not installed — WASM Gate not run (skip != pass)")
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b"NOPE\x01\x00\x00\x00garbage-past-the-magic")
    service = AnalysisService()
    try:
        info = service.wasm_info(str(bad))
        assert not info.ok and info.error is not None
        assert info.error.code == "backend_error", info.error
        assert "magic" in str(info.error.details.get("stderr", "")).lower()

        wat = service.wasm_wat(str(bad))
        assert not wat.ok and wat.error is not None
        assert wat.error.code == "backend_error", wat.error

        # And a valid module through the same reader still succeeds, so the fix
        # rejects only genuine failures rather than every non-zero-looking run.
        good = tmp_path / "min.wasm"
        good.write_bytes(b"\x00asm\x01\x00\x00\x00")
        ok = service.wasm_info(str(good))
        assert ok.ok and ok.data is not None, ok.error
        assert "wasm" in ok.data["objdump"].lower()
    finally:
        service.close_all()
