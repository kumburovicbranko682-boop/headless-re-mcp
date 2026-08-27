"""Web CDP WASM gate: a real module in a live page is found and its bytes fetched.

``test_web_cdp_open_and_inspect`` drives scripts/console/dom over a ``data:`` URL,
and the capture gate covers ``network_get``; nothing exercises the WASM
inspection workflow the Web track advertises -- ``web.wasm_list``
(``Debugger.scriptParsed`` with ``scriptLanguage == WebAssembly``) followed by
``web.script_source``. Both are version-sensitive CDP surfaces: on modern
Chromium ``Debugger.getScriptSource`` returns an *empty* ``scriptSource`` for a
``wasm://`` script (the module comes back in a ``bytecode`` field), so a drift
there passes every fake-based test and only fails against a real browser -- which
is exactly what left ``web.script_source`` returning nothing for WASM until it
learned to read the bytecode.

This gate serves a page that instantiates a real WASM module, opens it through
the real CDP browser, and pins that ``wasm_list`` surfaces the module as a
WebAssembly script and that ``script_source`` returns the real module bytes
(magic + size) -- and, when wabt is present, that the spilled module disassembles.
Skips (skip != pass) when Playwright / Chromium is not installed.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# A real (tiny) module: magic + version, two exported functions (add / sub),
# compiled from WAT by wabt's wat2wasm. Instantiating it in the page makes
# Chromium report a wasm:// script over CDP.
_WASM_B64 = "AGFzbQEAAAABBwFgAn9/AX8DAwIAAAcNAgNhZGQAAANzdWIAAQoRAgcAIAAgAWoLBwAgACABaws="

_PAGE = (
    "<!doctype html><html><head><title>wasmgate</title></head><body>hi"
    "<script>"
    f"const b64='{_WASM_B64}';"
    "const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));"
    "WebAssembly.instantiate(bytes).then(r=>{window.__w=r.instance.exports.add(2,3);});"
    "</script></body></html>"
)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = _PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass  # keep the test output quiet


@pytest.mark.integration
def test_web_wasm_list_and_source_over_a_real_module() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web WASM Gate not run (skip != pass)")

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    origin_port = origin.server_address[1]
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    service = AnalysisService()
    try:
        url = f"http://127.0.0.1:{origin_port}/"
        created = service.create_session(url, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )

        # WebAssembly.instantiate resolves a beat after DOMContentLoaded, so the
        # wasm:// script arrives after web.open returns. Poll for it.
        deadline = time.monotonic() + 15.0
        wasm_script = None
        while time.monotonic() < deadline:
            listed = service.web_wasm_list(session_id, limit=100)
            assert listed.ok, listed.error
            if listed.data["total"] > 0:
                wasm_script = listed.data["scripts"][0]
                break
            time.sleep(0.1)
        assert wasm_script is not None, "the instantiated WASM module was never surfaced"
        # wasm_list is the wasm_only filter over scriptParsed: it must have kept
        # the module because CDP reported scriptLanguage WebAssembly, not JS.
        assert str(wasm_script["language"]).lower() == "webassembly"
        assert str(wasm_script["url"]).startswith("wasm://")

        # script_source over a wasm:// script: modern CDP gives no text, so this
        # must return the real module bytes off the response's bytecode field.
        got = service.web_script_source(session_id, wasm_script["scriptId"])
        assert got.ok, got.error
        assert got.data["language"] == "webassembly"
        assert got.data["source"] == ""
        assert got.data["bytes"] > 0
        source_path = Path(got.data["source_path"])
        assert source_path.is_file()
        raw = source_path.read_bytes()
        assert raw[:4] == b"\x00asm", "spilled artifact is not a real WASM module"
        assert len(raw) == got.data["bytes"]

        # The whole point is that the dumped module is usable: when wabt is here,
        # web.script_source -> wasm.wat round-trips to a real disassembly.
        if WasmClient().available:
            wat = service.wasm_wat(str(source_path))
            assert wat.ok, wat.error
            assert "(module" in wat.data["wat"]
            assert "i32.add" in wat.data["wat"]
    finally:
        service.close_all()
