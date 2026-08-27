"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

# A minimal but genuine webpack bundle: three modules with an entry that pulls
# in the other two. webcrack recognises the webpack runtime and splits it into
# per-module files, which is the bundle-unpacking path js.deobfuscate never
# exercises.
_WEBPACK_BUNDLE = """
(function (modules) {
  var installed = {};
  function require(id) {
    if (installed[id]) return installed[id].exports;
    var m = (installed[id] = { exports: {} });
    modules[id](m, m.exports, require);
    return m.exports;
  }
  return require(0);
})([
  function (module, exports, require) {
    var greet = require(1);
    var math = require(2);
    module.exports = greet.hello("world") + " sum=" + math.add(2, 3);
  },
  function (module, exports) {
    exports.hello = function (name) { return "hello " + name; };
  },
  function (module, exports) {
    exports.add = function (a, b) { return a + b; };
  },
]);
"""

# A real WebAssembly module in text form: one exported function that adds its
# two i32 arguments. Compiled to bytes with wat2wasm so wasm2wat / wasm-objdump
# have genuine type, function, export and code sections to report.
_WAT_SOURCE = """
(module
  (func $add (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (export "add" (func $add)))
"""


def _wat2wasm(tmp_path: Path) -> Path:
    tool = shutil.which("wat2wasm")
    if tool is None:
        pytest.skip("wat2wasm (wabt) not installed — cannot build a WASM fixture (skip != pass)")
    wat = tmp_path / "add.wat"
    wat.write_text(_WAT_SOURCE, encoding="utf-8")
    module = tmp_path / "add.wasm"
    result = subprocess.run(
        [tool, str(wat), "-o", str(module)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 or not module.is_file():
        pytest.skip(f"wat2wasm could not build the WASM fixture: {result.stderr[:400]}")
    return module


def _service_with_artifacts(tmp_path: Path) -> AnalysisService:
    """A service whose artifact root is inside tmp so unpack output stays there."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)

# A distinct page so a navigation is observable in both the navigate result and
# the following DOM snapshot.
_SECOND_URL = (
    "data:text/html,"
    "<html><head><title>second-page</title></head><body>bye</body></html>"
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
def test_web_cdp_screenshot_navigate_source_and_har(tmp_path: Path) -> None:
    """The read tools past inspect: screenshot, script.source, navigate, HAR.

    test_web_cdp_open_and_inspect covers scripts/console/dom; the artifact- and
    navigation-producing paths had no live coverage. A tmp artifact root keeps
    the PNG/HAR the tools write inside the test's own directory.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = _service_with_artifacts(tmp_path)
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
            # status is a live, web-targeted page identity, no browser relaunch.
            status = service.web_status(session_id)
            assert status.ok, status.error
            assert status.data["open"] is True
            assert status.data["target"] == "web"

            # screenshot writes a real PNG artifact under the session's dir.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            png = Path(shot.data["path"])
            assert png.is_file()
            assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

            # at least one parsed script has a source retrievable over CDP.
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            listed = scripts.data["scripts"]
            assert listed, "Debugger.scriptParsed produced no scripts for the page"
            fetched = None
            for entry in listed[:5]:
                script_id = entry.get("scriptId")
                if script_id is None:
                    continue
                candidate = service.web_script_source(session_id, str(script_id))
                if candidate.ok:
                    fetched = candidate
                    break
            assert fetched is not None, "no parsed script had a retrievable source"
            assert isinstance(fetched.data["source"], str)
            assert fetched.data["bytes"] >= 0

            # navigation changes the page both the result and the DOM snapshot see.
            nav = service.web_navigate(session_id, _SECOND_URL, timeout=30.0)
            assert nav.ok, nav.error
            assert "second" in nav.data["title"]
            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert "second" in dom.data["title"]

            # HAR export writes a file with a coherent envelope.
            har = service.web_har_export(session_id)
            assert har.ok, har.error
            assert Path(har.data["path"]).is_file()
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


_NET_PAGE = (
    b"<html><head><title>net-gate</title></head><body>"
    b"<script>fetch('/data.json').then(r => r.json());</script>"
    b"</body></html>"
)
_NET_JSON = b'{"marker":"web-net-capture-42"}'


@contextmanager
def _fetch_origin_server() -> Iterator[int]:
    """A local origin whose page fetches a same-origin JSON subresource.

    Same-origin keeps the response body readable over CDP (a cross-origin,
    non-CORS body comes back opaque), so web.network.get can return it verbatim.
    Binding port 0 lets the OS pick a free port.
    """

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
            if self.path.startswith("/data.json"):
                body, ctype = _NET_JSON, "application/json"
            else:
                body, ctype = _NET_PAGE, "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


@pytest.mark.integration
def test_web_cdp_captures_a_network_request(tmp_path: Path) -> None:
    """Live web.network.list / web.network.get: a real fetch is recorded and read back.

    The other CDP gates never route a request the network recorder would see, so
    the network tools -- much of the point of driving a browser for RE -- had no
    live coverage. This serves a page that fetches a same-origin JSON subresource
    and asserts the recorder lists that request with its real status and that
    web.network.get hands back the exact bytes the origin sent, then that an
    unknown request id is a structured not_found. Skips only when
    Playwright/Chromium is absent (skip != pass).
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = _service_with_artifacts(tmp_path)
    with _fetch_origin_server() as port:
        try:
            created = service.create_session(f"http://127.0.0.1:{port}/page", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    f"chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # The fetch is async; poll until the recorder has the response.
                entry = None
                deadline = time.monotonic() + 15.0
                while time.monotonic() < deadline:
                    listed = service.web_network_list(session_id)
                    assert listed.ok, listed.error
                    for candidate in listed.data["requests"]:
                        url = str(candidate.get("url"))
                        if "/data.json" in url and candidate.get("status") is not None:
                            entry = candidate
                            break
                    if entry is not None:
                        break
                    time.sleep(0.1)
                assert entry is not None, "recorder never saw the same-origin fetch"
                assert entry["method"] == "GET"
                assert entry["status"] == 200
                assert "application/json" in str(entry["mimeType"])

                got = service.web_network_get(session_id, str(entry["requestId"]))
                assert got.ok, got.error
                assert got.data["body"] == _NET_JSON.decode()
                assert got.data["base64_encoded"] is False
                assert got.data["body_truncated"] is False
                assert "body_error" not in got.data

                # An id the recorder never saw is a structured not_found, not a crash.
                missing = service.web_network_get(session_id, "no-such-request")
                assert not missing.ok
                assert missing.error is not None
                assert missing.error.code == "not_found"
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()


# Canonical "add(i32, i32) -> i32" module, hand-encoded so the gate needs no
# wabt: magic+version, then the type / function / export / code sections. A page
# that instantiates it makes Chromium parse a real WebAssembly script.
_WASM_ADD_MODULE = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
    ]
)


@pytest.mark.integration
def test_web_cdp_lists_a_wasm_module() -> None:
    """Live web.wasm.list: a page that instantiates WebAssembly is parsed as such.

    web.wasm.list (web.scripts filtered to WebAssembly) had no live coverage;
    the inspect gate only ever saw JavaScript scripts. This opens a page that
    instantiates a hand-encoded module and asserts Chromium reports it as a
    WebAssembly script with a wasm:// URL, so the WASM discovery path is proven
    end to end. Skips only when Playwright/Chromium is absent (skip != pass).
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    import base64

    b64 = base64.b64encode(_WASM_ADD_MODULE).decode("ascii")
    page = (
        "data:text/html,"
        "<html><head><title>wasm-gate</title><script>"
        f"const b=Uint8Array.from(atob('{b64}'),c=>c.charCodeAt(0));"
        "WebAssembly.instantiate(b).then(m=>{window.__sum=m.instance.exports.add(2,3);});"
        "</script></head><body>x</body></html>"
    )
    service = AnalysisService()
    try:
        created = service.create_session(page, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # scriptParsed for the compiled module is async; poll for it.
            wasm_scripts: list[dict[str, object]] = []
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                listed = service.web_wasm_list(session_id)
                assert listed.ok, listed.error
                wasm_scripts = list(listed.data["scripts"])
                if wasm_scripts:
                    break
                time.sleep(0.1)
            assert wasm_scripts, "no WebAssembly script was reported for the page"
            first = wasm_scripts[0]
            assert str(first["language"]).lower() == "webassembly"
            assert str(first["url"]).startswith("wasm://")
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
def test_js_beautify_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_beautify(str(_JS_FIXTURE))
        assert result.ok, result.error
        # webcrack strips comments and dead scaffolding, so the readable form is
        # not necessarily larger than the source; assert it is real, non-empty
        # JavaScript rather than a size relation.
        assert result.data["bytes"] > 0
        assert "function" in result.data["code"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_splits_a_webpack_bundle(tmp_path: Path) -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    bundle = tmp_path / "bundle.js"
    bundle.write_text(_WEBPACK_BUNDLE, encoding="utf-8")
    service = _service_with_artifacts(tmp_path)
    try:
        # limit=2 forces paging even though the bundle yields more files.
        first = service.js_unpack_bundle(str(bundle), offset=0, limit=2)
        assert first.ok, first.error
        data = first.data
        # webcrack emits per-module files (index.js + 1.js + 2.js) plus its
        # bundle.json/deobfuscated.js, so a recognised 3-module bundle is
        # several files, not one.
        assert data["file_count"] >= 3
        assert data["total"] == data["file_count"]
        assert data["count"] == 2
        assert data["offset"] == 0
        assert data["has_more"] is True
        assert len(data["files"]) == 2
        assert Path(data["output_dir"]).is_dir()

        # The second page continues where the first stopped and is disjoint.
        second = service.js_unpack_bundle(str(bundle), offset=2, limit=100)
        assert second.ok, second.error
        assert second.data["offset"] == 2
        assert set(first.data["files"]).isdisjoint(second.data["files"])
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


@pytest.mark.integration
def test_wasm_wat_and_info_on_a_real_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = _wat2wasm(tmp_path)
    service = AnalysisService()
    try:
        wat = service.wasm_wat(str(module))
        assert wat.ok, wat.error
        text = wat.data["wat"]
        # The round-tripped text must carry the function and its export back.
        assert "func" in text
        assert "i32.add" in text
        assert "export" in text and "add" in text

        info = service.wasm_info(str(module))
        assert info.ok, info.error
        objdump = info.data["objdump"]
        # wasm-objdump -h -x names each section it walks; a real module has at
        # least the type/function/export/code sections.
        assert "Type" in objdump
        assert "Export" in objdump
        assert "Code" in objdump
    finally:
        service.close_all()
