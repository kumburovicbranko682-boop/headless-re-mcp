"""WASM capture live gate: browser-side module capture through to wasm2wat.

The web line advertises a WebAssembly story -- ``web.scripts`` has a
``wasm_only`` filter keyed on CDP's ``scriptLanguage``, ``network_get`` decodes
base64 binary bodies (the comment there names wasm explicitly), and the jsre
line ships a wabt-backed ``wasm.wat`` -- yet none of it ever saw a real module:
no test loaded WebAssembly in a browser, the ``wasm_only`` filter and the
binary-body decode path only ran against mocks, and ``wasm2wat`` only ran in
its own gate against a fixture no browser produced. This gate serves a page
that fetches and instantiates a real module, then walks the whole RE pipeline:
the wasm script surfaces via ``wasm_only``, the exact module bytes come back
through the binary body path, and wabt disassembles those same bytes to WAT.

Skip != pass: each test skips with a reason when its dependency (chromium,
wabt) is absent and runs for real when present. CI installs both, so a skip
there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.backends.web import WebBackend, WebError

# wat2wasm output for:
#   (module (func (export "add") (param i32 i32) (result i32)
#     local.get 0 local.get 1 i32.add))
# Embedded so the capture test needs no wabt; the disassembly test asserts
# wasm2wat recovers exactly this export and opcode from these bytes.
_WASM_MODULE = bytes.fromhex(
    "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b"
)

# The page fetches the module, instantiates it and logs add(5, 7), so a console
# line proves the captured bytes are a *working* module, not just served bytes.
_INDEX_HTML = (
    b"<!doctype html><html><head><title>wasm-gate</title></head><body>\n"
    b"<script>\n"
    b"fetch('/add.wasm').then(r => r.arrayBuffer())\n"
    b"  .then(b => WebAssembly.instantiate(b))\n"
    b"  .then(m => console.log('wasm_add ' + m.instance.exports.add(5, 7)));\n"
    b"</script></body></html>"
)

_ROUTES: dict[str, tuple[bytes, str]] = {
    "/": (_INDEX_HTML, "text/html"),
    "/add.wasm": (_WASM_MODULE, "application/wasm"),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass

    def do_GET(self) -> None:
        body, ctype = _ROUTES.get(self.path, (b"not found", "text/plain"))
        self.send_response(200 if self.path in _ROUTES else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _local_site() -> Iterator[str]:
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _wait_for(predicate: Callable[[], bool], *, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


@pytest.mark.integration
def test_web_backend_captures_wasm_module_and_binary_body(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — wasm capture Gate not run (skip != pass)")

    backend = WebBackend()
    with _local_site() as url:
        try:
            backend.open("wasm", url, headless=True, timeout=30.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        try:
            # Instantiation is async; the console line is the completion signal.
            assert _wait_for(
                lambda: any(
                    "wasm_add" in str(c.get("text"))
                    for c in backend.console("wasm", limit=100)["console"]
                )
            ), "the module never instantiated (no wasm_add console line)"
            texts = [str(c.get("text")) for c in backend.console("wasm", limit=100)["console"]]
            # add(5, 7) == 12 proves the captured module actually executed.
            assert any("wasm_add 12" in t for t in texts)

            # The wasm_only filter must surface the module as a WebAssembly
            # script, distinct from the page's JavaScript.
            wasm_scripts = backend.scripts("wasm", wasm_only=True, limit=100)
            assert wasm_scripts["count"] >= 1, "no WebAssembly script was captured"
            entry = wasm_scripts["scripts"][0]
            assert str(entry.get("language")).lower() == "webassembly"
            assert str(entry.get("url")).startswith("wasm://")

            # network_get must decode the base64 binary body and spill the real
            # bytes: the artifact must be the exact module the server sent.
            requests = backend.network_list("wasm", limit=100)["requests"]
            wasm_req = next((r for r in requests if "add.wasm" in str(r.get("url"))), None)
            assert wasm_req is not None, "the module request was not recorded"
            body = backend.network_get("wasm", str(wasm_req["requestId"]), tmp_path)
            assert body.get("base64_encoded") is True
            assert body.get("body_bytes") == len(_WASM_MODULE)
            assert "body_path" in body, "binary body was not spilled to an artifact"
            assert Path(str(body["body_path"])).read_bytes() == _WASM_MODULE
        finally:
            backend.close_all()


@pytest.mark.integration
def test_wasm2wat_disassembles_the_captured_module(tmp_path: Path) -> None:
    client = WasmClient()
    if not client.available:
        pytest.skip("wabt (wasm2wat) not installed — Gate not run (skip != pass)")

    # The same bytes the browser test proves come back through network_get.
    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_MODULE)

    result = client.wat(module)
    wat = str(result.get("wat", ""))
    assert "(module" in wat
    # Real disassembly recovers the export by name and the addition opcode.
    assert '(export "add"' in wat
    assert "i32.add" in wat
