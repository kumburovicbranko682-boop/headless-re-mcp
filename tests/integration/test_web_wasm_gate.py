"""Live Web dynamic gate: CDP fetches a JS script's source and a Wasm module's WAT.

The existing CDP gate only checks web.scripts returns a list; nothing exercised
web.script.source (fetching a script's actual text) or web.wasm.list. This gate
drives a headless Chromium at a local origin whose page loads a JS file and
instantiates a real WebAssembly module, then asserts:

  * web.script.source on the JS script returns its text (a known marker), and
  * web.wasm.list surfaces the module, whose web.script.source is the WAT
    disassembly (Debugger.getScriptSource yields no scriptSource for Wasm, so the
    backend must fall back to Debugger.disassembleWasmModule -- without that fix
    Wasm modules came back with an empty source).

skip != pass: skips cleanly when playwright/Chromium is unavailable.
"""

from __future__ import annotations

import base64
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# A minimal, valid Wasm module exporting add(i32, i32) -> i32. Kept as raw bytes
# so the gate needs no wabt to build it; the browser instantiates it and CDP
# reports it as a WebAssembly script.
_WASM_ADD = bytes(
    [
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
    ]
)
_MARKER = "WEB-SCRIPTSRC-OK"
_WASM_B64 = base64.b64encode(_WASM_ADD).decode()
# Built by concatenation (not % / f-string) so the JS braces need no escaping.
_APP_JS = (
    "\n".join(
        [
            'function headlessMarker() { return "' + _MARKER + '"; }',
            "window.__marker = headlessMarker();",
            'var _b = Uint8Array.from(atob("'
            + _WASM_B64
            + '"), function (c) { return c.charCodeAt(0); });',
            "WebAssembly.instantiate(_b).then(function (r) {",
            "  window.__wasmAdd = r.instance.exports.add(2, 3);",
            "});",
        ]
    )
    + "\n"
)
_APP_JS_BYTES = _APP_JS.encode()
_DOC_HTML = (
    b"<!doctype html><html><head><title>wasm-gate</title>"
    b'<script src="app.js"></script></head><body>ok</body></html>'
)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.split("?", 1)[0] == "/app.js":
            body, ctype = _APP_JS_BYTES, "application/javascript"
        else:
            body, ctype = _DOC_HTML, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence the stdlib access log
        return


@contextmanager
def _local_origin() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, name="gate-wasm-origin", daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _await_scripts(service: AnalysisService, session_id: str) -> tuple[dict | None, dict | None]:
    """Poll until both the app.js JS script and a Wasm module are parsed."""
    deadline = time.monotonic() + 15.0
    js: dict | None = None
    wasm: dict | None = None
    while time.monotonic() < deadline:
        listed = service.web_scripts(session_id, limit=500)
        assert listed.ok, listed.error
        for script in listed.data["scripts"]:
            if str(script.get("url", "")).endswith("app.js"):
                js = script
        wasm_listed = service.web_wasm_list(session_id, limit=100)
        assert wasm_listed.ok, wasm_listed.error
        if wasm_listed.data["scripts"]:
            wasm = wasm_listed.data["scripts"][0]
        if js and wasm:
            break
        time.sleep(0.15)
    return js, wasm


@pytest.mark.integration
def test_web_cdp_fetches_js_source_and_wasm_wat() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web WASM Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _local_origin() as origin_port:
            created = service.create_session(f"http://127.0.0.1:{origin_port}/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                js, wasm = _await_scripts(service, session_id)
                assert js is not None, "the app.js script was not reported by CDP"
                assert wasm is not None, "no WebAssembly module was reported by CDP"
                assert str(wasm["language"]).lower() == "webassembly", wasm

                js_source = service.web_script_source(session_id, js["scriptId"])
                assert js_source.ok, js_source.error
                assert js_source.data["language"] == "javascript"
                body = js_source.data["source"]
                if js_source.data.get("source_path"):
                    body = Path(js_source.data["source_path"]).read_text(encoding="utf-8")
                assert "headlessMarker" in body, body[:200]
                assert _MARKER in body, body[:200]

                wat = service.web_script_source(session_id, wasm["scriptId"])
                assert wat.ok, wat.error
                assert wat.data["language"] == "webassembly", wat.data
                text = wat.data["source"]
                assert text, "Wasm script source was empty (disassembly missing?)"
                assert "i32.add" in text, text
                assert '"add"' in text, text
                assert "local.get" in text, text
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
