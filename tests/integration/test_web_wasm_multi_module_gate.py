"""Live gate: two WASM modules in one page stay distinct end to end.

The existing WASM gates load a single module, so nothing proves the backend
keeps *multiple* modules apart. A page that instantiates two modules exercises
the risky bit: scripts(wasm_only) must list both, and script_source must key the
spilled bytes by scriptId so each id yields its own module -- not a shared or
last-wins blob. The two fixtures are the same 41-byte length but differ only in
the export name and the arithmetic opcode, so a mix-up cannot hide behind a size
check; only correct per-id routing passes.

The gate loads ``add`` (i32.add) and ``mul`` (i32.mul), waits for both to be
discovered as WebAssembly scripts and to run (add(2,3)==5, mul(2,3)==6), then
asserts each module found by URL spills to its own file with its own bytes and
disassembles through wabt to its own export and opcode -- add's wat carries
i32.add and not i32.mul, and vice versa. Distinct bytes at equal length plus
per-module wabt output prove the backend routes source by scriptId rather than
sharing one blob. skip != pass when chromium or wabt is missing.
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

# Two modules identical in shape and length (41 bytes) but differing in the
# export name (add/mul) and the opcode (i32.add 0x6A / i32.mul 0x6C).
_WASM_ADD = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,  # export "add"
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,  # i32.add
    ]
)
_WASM_MUL = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x6D, 0x75, 0x6C, 0x00, 0x00,  # export "mul"
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6C, 0x0B,  # i32.mul
    ]
)
# Both modules are instantiated in parallel via Promise.all. Awaiting two
# streaming instantiations *sequentially* in one page wedges the second fetch in
# headless Chromium (the first module's response stream stays locked); the
# parallel form is reliable and still keeps each module's /*.wasm source URL.
_PAGE = (
    "<!doctype html><html><head><title>multi-wasm</title></head>"
    "<body><h1>multi wasm</h1><script>"
    "(async () => { try {"
    " const [a, m] = await Promise.all(["
    "  WebAssembly.instantiateStreaming(fetch('/add.wasm')),"
    "  WebAssembly.instantiateStreaming(fetch('/mul.wasm'))]);"
    " console.log('ADD=' + a.instance.exports.add(2, 3));"
    " console.log('MUL=' + m.instance.exports.mul(2, 3));"
    " } catch (e) { console.log('WASM_ERROR=' + e); } })();"
    "</script></body></html>"
)


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path.startswith("/add.wasm"):
            body, ctype = _WASM_ADD, "application/wasm"
        elif self.path.startswith("/mul.wasm"):
            body, ctype = _WASM_MUL, "application/wasm"
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
def test_web_two_wasm_modules_stay_distinct(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — multi-WASM Gate not run (skip != pass)")
    wasm = WasmClient()
    if not wasm.available:
        pytest.skip("wabt (wasm2wat) not installed — multi-WASM Gate not run (skip != pass)")

    assert _WASM_ADD != _WASM_MUL and len(_WASM_ADD) == len(_WASM_MUL)  # design invariant

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    try:
        try:
            backend.open("mw", f"http://127.0.0.1:{port}/page", headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        # Wait until both modules are discovered as WebAssembly scripts and both
        # have run to their distinct results (add(2,3)==5, mul(2,3)==6), proving
        # two live instances rather than one module seen twice.
        def _both_seen(texts: list[str]) -> bool:
            urls = {str(s["url"]) for s in backend.scripts("mw", wasm_only=True)["scripts"]}
            discovered = any(u.endswith("/add.wasm") for u in urls) and any(
                u.endswith("/mul.wasm") for u in urls
            )
            ran = any("ADD=5" in t for t in texts) and any("MUL=6" in t for t in texts)
            return discovered and ran

        deadline = time.monotonic() + 30.0
        texts: list[str] = []
        while time.monotonic() < deadline:
            texts = [str(i.get("text")) for i in backend.console("mw", limit=200)["console"]]
            assert not any("WASM_ERROR" in t for t in texts), texts
            if _both_seen(texts):
                break
            time.sleep(0.1)

        assert any("ADD=5" in t for t in texts), texts
        assert any("MUL=6" in t for t in texts), texts

        # Both modules are discovered, each with its own scriptId and URL.
        listed = backend.scripts("mw", wasm_only=True)
        assert listed["total"] >= 2, listed
        by_url = {str(s["url"]): s for s in listed["scripts"]}
        add_mod = next((s for u, s in by_url.items() if u.endswith("/add.wasm")), None)
        mul_mod = next((s for u, s in by_url.items() if u.endswith("/mul.wasm")), None)
        assert add_mod is not None and mul_mod is not None, list(by_url)
        assert str(add_mod["language"]).lower() == "webassembly", add_mod
        assert str(mul_mod["language"]).lower() == "webassembly", mul_mod
        add_id = str(add_mod["scriptId"])
        mul_id = str(mul_mod["scriptId"])
        assert add_id != mul_id, (add_id, mul_id)

        # The decisive check: script_source keys by scriptId, so each id spills
        # its own module -- same size, different bytes, correctly routed.
        add_src = backend.script_source("mw", add_id, tmp_path / "artifacts")
        mul_src = backend.script_source("mw", mul_id, tmp_path / "artifacts")
        add_path = Path(add_src["source_path"])
        mul_path = Path(mul_src["source_path"])
        assert add_path != mul_path, (add_path, mul_path)
        add_bytes = add_path.read_bytes()
        mul_bytes = mul_path.read_bytes()
        assert add_bytes == _WASM_ADD, add_bytes.hex()
        assert mul_bytes == _WASM_MUL, mul_bytes.hex()
        assert add_bytes != mul_bytes  # not a shared / last-wins blob

        # Static analysis confirms each captured module carries its own logic:
        # add's disassembly has i32.add and the "add" export and not the other,
        # and mul's the mirror image. wabt analysing one never leaks the other.
        add_wat = str(wasm.wat(add_path)["wat"])
        mul_wat = str(wasm.wat(mul_path)["wat"])
        assert '(export "add"' in add_wat and "i32.add" in add_wat, add_wat
        assert "i32.mul" not in add_wat and '(export "mul"' not in add_wat, add_wat
        assert '(export "mul"' in mul_wat and "i32.mul" in mul_wat, mul_wat
        assert "i32.add" not in mul_wat and '(export "add"' not in mul_wat, mul_wat

        # Both modules also show up as distinct captured network requests.
        requests = backend.network_list("mw")["requests"]
        req_by_url = {str(r["url"]): r for r in requests}
        for suffix in ("/add.wasm", "/mul.wasm"):
            hit = next((r for u, r in req_by_url.items() if u.endswith(suffix)), None)
            assert hit is not None, (suffix, list(req_by_url))
            assert hit["status"] == 200, hit
            assert str(hit["mimeType"]) == "application/wasm", hit
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
