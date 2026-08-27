"""Live gate: a browser-captured WASM module feeds the wabt static path.

Two capabilities already have gates in isolation -- the web line discovers a
running module and spills its bytes through script_source, and the wabt line
disassembles a wat2wasm-assembled fixture -- but nothing links them. This gate
runs the chain: instantiate a module in Chromium, pull it back with
script_source (the base64 bytecode branch that was silently broken), and hand
the spilled .wasm straight to WasmClient. It asserts wabt disassembles the
dynamically captured module and that the exported name and opcode survive the
round trip through the browser, proving the dynamic capture is analysis-ready
rather than merely byte-identical. skip != pass when chromium or wabt is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.backends.web import WebBackend, WebError

# (module (func (export "add") (param i32 i32) (result i32)
#   local.get 0 local.get 1 i32.add))
_WASM_ADD = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,  # type (i32 i32)->i32
        0x03, 0x02, 0x01, 0x00,  # func -> type 0
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,  # export "add"
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,  # code
    ]
)
_PAGE = (
    "<!doctype html><html><head><title>wasm-chain</title></head>"
    "<body><h1>wasm chain</h1><script>"
    "(async () => { try {"
    " const res = await WebAssembly.instantiateStreaming(fetch('/add.wasm'));"
    " console.log('WASM_MARKER=' + res.instance.exports.add(2, 3));"
    " } catch (e) { console.log('WASM_ERROR=' + e); } })();"
    "</script></body></html>"
)


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path.startswith("/add.wasm"):
            body, ctype = _WASM_ADD, "application/wasm"
        else:
            body, ctype = _PAGE.encode("utf-8"), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


@pytest.mark.integration
def test_web_captured_wasm_disassembles_through_wabt(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — WASM chain Gate not run (skip != pass)")
    wasm = WasmClient()
    if not wasm.available:
        pytest.skip("wabt (wasm2wat) not installed — WASM chain Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    try:
        try:
            backend.open("chain", f"http://127.0.0.1:{port}/page", headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        # Wait for the module to be parsed and to actually run (add(2,3) == 5).
        script_id: str | None = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            scripts = backend.scripts("chain", wasm_only=True)
            console = backend.console("chain", limit=200)
            ran = any("WASM_MARKER=5" in str(i.get("text")) for i in console["console"])
            if scripts["total"] >= 1 and ran:
                script_id = str(scripts["scripts"][0]["scriptId"])
                break
            time.sleep(0.1)
        assert script_id is not None, "wasm module never parsed/ran"

        # Dynamic capture: script_source spills the module bytes as a real .wasm.
        src = backend.script_source("chain", script_id, tmp_path / "artifacts")
        assert src.get("wasm") is True, src
        assert src["bytes"] == len(_WASM_ADD), src
        module_path = Path(src["source_path"])
        assert module_path.read_bytes() == _WASM_ADD

        # Static analysis of that captured module: wasm2wat disassembles it and
        # the export/opcode survive the capture.
        wat = wasm.wat(module_path)
        text = str(wat["wat"])
        assert wat["bytes"] > 0
        assert "(module" in text, text
        assert '(export "add"' in text, text
        assert "(param i32 i32) (result i32)" in text, text
        assert "i32.add" in text, text

        # wasm-objdump on the same captured file names the section table, the
        # function signature and the export mapping.
        info = wasm.info(module_path)
        dump = str(info["objdump"])
        assert "file format wasm" in dump, dump
        assert "Export" in dump and '"add"' in dump, dump
        assert "(i32, i32) -> i32" in dump, dump
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
