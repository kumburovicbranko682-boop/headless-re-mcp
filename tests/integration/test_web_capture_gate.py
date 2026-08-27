"""Live CDP capture gate: the capture must describe the page that really loaded.

The basic web gate proves open/inspect calls succeed against a data: URL, but
every list it checks is allowed to be empty. This gate serves a real page --
an external script, a JSON API the page fetches, and a WebAssembly module it
instantiates -- and asserts the capture surfaces carry that page's actual
content: console text, script source, network bodies (text and binary spill),
the wasm listing, navigation, the HAR export, and a screenshot.
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_MARKER = "cdp-marker-f00d"

_PAGE_HTML = (
    b"<html><head><title>capture-gate</title>"
    b'<script src="/app.js"></script>'
    b"</head><body>hello capture</body></html>"
)

_SECOND_HTML = b"<html><head><title>second-page</title></head><body>after nav</body></html>"

_APP_JS = """
const MARKER = "__MARKER__";
console.log("gate-console:" + MARKER);
fetch("/api/data")
  .then((r) => r.json())
  .then((d) => console.log("gate-api:" + d.answer));
fetch("/mod.wasm")
  .then((r) => r.arrayBuffer())
  .then((b) => {
    // Synchronous compile on purpose: with the CDP Debugger domain attached
    // (which the capture layer enables to list scripts), the async
    // WebAssembly.instantiate promise intermittently never settles in
    // headless chromium -- an upstream V8 race, reproduced ~1 in 10 runs.
    // The sync API takes a different compile path, still emits
    // Debugger.scriptParsed, and never stalled in 80 attempts.
    const inst = new WebAssembly.Instance(new WebAssembly.Module(b));
    console.log("gate-wasm:" + inst.exports.add(40, 2));
  })
  .catch((e) => console.log("gate-wasm-error:" + e));
""".replace("__MARKER__", _MARKER).encode()

_API_BODY = b'{"answer": "capture-42"}'

# The canonical smallest useful module: (func (export "add") (param i32 i32)
# (result i32) local.get 0 local.get 1 i32.add). Instantiating it makes the
# page's wasm real to the CDP debugger, not just a fetched blob.
_WASM_ADD = bytes.fromhex(
    "0061736d01000000"  # magic + version
    "01070160027f7f017f"  # type: (i32, i32) -> i32
    "03020100"  # one function of type 0
    "070701036164640000"  # export "add"
    "0a09010700200020016a0b"  # body: local.get 0, local.get 1, i32.add
)

_ROUTES: dict[str, tuple[int, str, bytes]] = {
    "/": (200, "text/html", _PAGE_HTML),
    "/second": (200, "text/html", _SECOND_HTML),
    "/app.js": (200, "application/javascript", _APP_JS),
    "/api/data": (200, "application/json", _API_BODY),
    "/mod.wasm": (200, "application/wasm", _WASM_ADD),
}


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        status, content_type, payload = _ROUTES.get(self.path, (404, "text/plain", b"not found"))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence the default stderr access log."""


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:  # noqa: BLE001
        return False
    return True


def _wait_until(predicate: Callable[[], bool], what: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {what}")


@contextlib.contextmanager
def _origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    threading.Thread(target=server.serve_forever, name="origin-http", daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.integration
def test_cdp_capture_describes_the_page_that_really_loaded() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web capture Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _origin() as base:
            created = service.create_session(f"{base}/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    f"chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Console capture must carry what the page really logged: the
                # static marker, the fetched API value, and the result computed
                # by the instantiated wasm export. Waiting on these also proves
                # the page's own fetches completed before the checks below.
                def _console_lines() -> list[str]:
                    got = service.web_console(session_id)
                    assert got.ok, got.error
                    entries = cast(list[dict[str, Any]], got.data["console"])
                    return [str(e.get("text") or "") for e in entries]

                expected_logs = {f"gate-console:{_MARKER}", "gate-api:capture-42", "gate-wasm:42"}
                _wait_until(
                    lambda: expected_logs.issubset(set(_console_lines())),
                    f"console to carry {sorted(expected_logs)}; saw {_console_lines()}",
                )

                # The external script must be listed, and its fetched source
                # must be the code the origin actually served.
                scripts = service.web_scripts(session_id, limit=1000)
                assert scripts.ok, scripts.error
                app_js = [
                    s
                    for s in cast(list[dict[str, Any]], scripts.data["scripts"])
                    if str(s.get("url") or "").endswith("/app.js")
                ]
                assert app_js, f"app.js missing from script list: {scripts.data}"
                source = service.web_script_source(session_id, str(app_js[0]["scriptId"]))
                assert source.ok, source.error
                assert _MARKER in source.data["source"]
                assert source.data["truncated"] is False

                # The instantiated module must show up in the wasm-only view.
                wasm = service.web_wasm_list(session_id)
                assert wasm.ok, wasm.error
                wasm_rows = cast(list[dict[str, Any]], wasm.data["scripts"])
                assert wasm_rows, "instantiated wasm module missing from wasm list"
                assert all(
                    str(row.get("language", "")).lower() == "webassembly" for row in wasm_rows
                )

                # The network capture must hold the document, the script, and
                # the API fetch, each with the status the origin sent.
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                rows = cast(list[dict[str, Any]], listing.data["requests"])
                by_url = {str(row["url"]): row for row in rows}
                for path in ("/", "/app.js", "/api/data", "/mod.wasm"):
                    row = by_url.get(f"{base}{path}")
                    assert row is not None, f"{path} missing from network capture: {sorted(by_url)}"
                    assert row["status"] == 200, f"{path}: {row}"
                assert by_url[f"{base}/api/data"]["mimeType"] == "application/json"

                # Text bodies come back inline and verbatim...
                api = service.web_network_get(
                    session_id, str(by_url[f"{base}/api/data"]["requestId"])
                )
                assert api.ok, api.error
                assert api.data["body"] == _API_BODY.decode()
                assert api.data["base64_encoded"] is False

                # ...and a binary body spills real bytes to an artifact.
                mod = service.web_network_get(
                    session_id, str(by_url[f"{base}/mod.wasm"]["requestId"])
                )
                assert mod.ok, mod.error
                assert mod.data["base64_encoded"] is True
                assert mod.data["body_bytes"] == len(_WASM_ADD)
                assert Path(str(mod.data["body_path"])).read_bytes() == _WASM_ADD

                # The HAR export must carry the same exchanges.
                har = service.web_har_export(session_id)
                assert har.ok, har.error
                entries = json.loads(Path(str(har.data["path"])).read_text(encoding="utf-8"))[
                    "log"
                ]["entries"]
                har_urls = {e["request"]["url"]: e["response"]["status"] for e in entries}
                assert har_urls.get(f"{base}/api/data") == 200

                # A screenshot of the live page must land as a real PNG.
                shot = service.web_screenshot(session_id)
                assert shot.ok, shot.error
                png = Path(str(shot.data["path"])).read_bytes()
                assert png.startswith(b"\x89PNG\r\n\x1a\n")

                # Navigation must actually move the page.
                moved = service.web_navigate(session_id, f"{base}/second")
                assert moved.ok, moved.error
                assert moved.data["title"] == "second-page"
                dom = service.web_dom_snapshot(session_id)
                assert dom.ok, dom.error
                assert "after nav" in dom.data["html"]
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
