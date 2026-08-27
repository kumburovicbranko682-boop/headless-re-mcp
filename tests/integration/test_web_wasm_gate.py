"""Live web WASM gate: a real module is discovered and its bytes retrievable.

The web line lists WASM inspection as a capability, but nothing exercised it
against a real module. This gate serves a tiny hand-assembled wasm module that
exports ``add``, instantiates it in a page, and asserts the module is captured
as a network request, discovered through scripts(wasm_only=True) with language
WebAssembly, and -- the part that was silently broken -- that script_source
hands back the module bytes.

Chrome delivers a wasm module's content with an empty ``scriptSource`` and the
bytes base64-encoded under ``bytecode``; the backend now decodes that and spills
a real .wasm, so this gate would fail (empty source) against the unfixed client.
skip != pass when playwright/chromium is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

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
    "<!doctype html><html><head><title>wasm-gate</title></head>"
    "<body><h1>wasm gate</h1><script>"
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
def test_web_wasm_module_is_discovered_and_its_bytes_retrievable(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web WASM Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    url = f"http://127.0.0.1:{port}/page"
    try:
        try:
            backend.open("wasm", url, headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        # Instantiation is async, so wait for the module to be parsed and run.
        script_id: str | None = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            wasm = backend.scripts("wasm", wasm_only=True)
            console = backend.console("wasm", limit=200)
            ran = any("WASM_MARKER=5" in str(i.get("text")) for i in console["console"])
            if wasm["total"] >= 1 and ran:
                script_id = str(wasm["scripts"][0]["scriptId"])
                break
            time.sleep(0.1)

        # The module executed: add(2, 3) == 5, proving it really instantiated.
        console = backend.console("wasm", limit=200)
        assert any("WASM_MARKER=5" in str(i.get("text")) for i in console["console"]), console

        # It is discoverable as a WebAssembly script filtered by wasm_only.
        wasm = backend.scripts("wasm", wasm_only=True)
        assert wasm["total"] >= 1, wasm
        module = wasm["scripts"][0]
        assert str(module["language"]).lower() == "webassembly", module
        assert str(module["url"]).endswith("/add.wasm"), module
        assert script_id is not None

        # script_source hands back the module bytes as a real .wasm (the branch
        # that was returning nothing before the bytecode fix).
        src = backend.script_source("wasm", script_id, tmp_path / "artifacts")
        assert src.get("wasm") is True, src
        assert src["bytes"] == len(_WASM_ADD), src
        module_path = Path(src["source_path"])
        blob = module_path.read_bytes()
        assert blob[:4] == b"\x00asm", blob[:8]
        assert blob == _WASM_ADD

        # The module also shows up as a captured network request.
        requests = backend.network_list("wasm")["requests"]
        wasm_req = next(
            (r for r in requests if str(r["url"]).endswith("/add.wasm")), None
        )
        assert wasm_req is not None, requests
        assert wasm_req["status"] == 200
        assert str(wasm_req["mimeType"]) == "application/wasm", wasm_req
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
