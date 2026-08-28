"""Web CDP capture gate: scripts, network bodies, and WASM from a real page.

``test_web_re_gate.py`` opens a ``data:`` page and checks three read tools
(scripts list, console, DOM). The capture surface that makes the Web line
useful for RE -- fetching a script's source, recording the network requests a
page makes and reading a response body back, and listing the WASM modules a
page instantiates -- had no coverage. This gate serves a small real site from a
localhost ``http.server`` (an external script, a JSON fetch, and a fetched +
instantiated WASM module), drives it through the live browser, and asserts the
values CDP hands back.

Everything is plain HTTP to 127.0.0.1, so it needs no external network. The
browser is optional: a machine without Playwright/Chromium skips with a reason,
and the hosted ``linux-integration`` CI job installs Chromium so this runs for
real on every push.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_MARKER = "cdp-gate-marker-9000"
_APP_JS = f'window.__marker = "{_MARKER}";\nfunction greet(name) {{ return "hi " + name; }}\n'
_DATA_JSON = '{"gate": "ok", "n": 7}'
# fixtures/web/sample.wat compiled with wat2wasm: an exported add(i32,i32)->i32,
# an exported global, and a memory. Embedded so the gate needs only a browser,
# not wabt, and the page can fetch + instantiate a genuine module.
_WASM_B64 = (
    "AGFzbQEAAAABBwFgAn9/AX8DAgEABQMBAAEGBgF/AEEqCwcW"
    "AwNhZGQAAAZhbnN3ZXIDAANtZW0CAAoJAQcAIAAgAWoL"
)
_WASM_BYTES = base64.b64decode(_WASM_B64)

_PAGE_HTML = """<!doctype html>
<html><head><title>cdp-gate</title><script src="/app.js"></script></head>
<body>hello
<script>
  window.__ready = false;
  Promise.all([
    fetch('/data.json').then(r => r.json()).then(d => { window.__data = d; }),
    fetch('/mod.wasm').then(r => r.arrayBuffer())
      .then(b => WebAssembly.instantiate(b))
      .then(m => { window.__sum = m.instance.exports.add(2, 3); })
  ]).then(() => { window.__ready = true; });
</script>
</body></html>
"""

_ROUTES: dict[str, tuple[bytes, str]] = {
    "/": (_PAGE_HTML.encode(), "text/html"),
    "/app.js": (_APP_JS.encode(), "application/javascript"),
    "/data.json": (_DATA_JSON.encode(), "application/json"),
    "/mod.wasm": (_WASM_BYTES, "application/wasm"),
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler dispatch name
        path = self.path.split("?", 1)[0]
        payload = _ROUTES.get(path)
        if payload is None:
            self.send_response(404)
            self.end_headers()
            return
        body, content_type = payload
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:  # silence the access log
        return


@contextmanager
def _origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:  # noqa: BLE001
        return False
    return True


def _poll(check: Callable[[], bool], *, what: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {what}")


@pytest.mark.integration
def test_web_cdp_captures_scripts_network_and_wasm(tmp_path: Path) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP capture Gate not run (skip != pass)")

    from dataclasses import replace

    from headless_re_mcp.config import Settings

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings=settings)
    try:
        with _origin() as base_url:
            created = service.create_session(base_url + "/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch "
                    f"({opened.error.code if opened.error else 'unknown'}) — skip != pass"
                )

            # The page fetches /data.json and /mod.wasm after load, so poll until
            # the network capture has seen every resource the page pulls.
            def _seen_all_requests() -> bool:
                listed = service.web_network_list(session_id, limit=1000)
                if not listed.ok:
                    return False
                urls = {r["url"] for r in listed.data["requests"]}
                return all(
                    any(u.endswith(path) for u in urls)
                    for path in ("/app.js", "/data.json", "/mod.wasm")
                )

            _poll(_seen_all_requests, what="the page's network requests")

            requests = service.web_network_list(session_id, limit=1000).data["requests"]
            by_suffix = {
                path: next(r for r in requests if r["url"].endswith(path))
                for path in ("/app.js", "/data.json", "/mod.wasm")
            }
            assert by_suffix["/data.json"]["method"] == "GET"

            # Reading a response body back is the core capture contract; wait for
            # the response to arrive before asking for its body.
            data_req_id = by_suffix["/data.json"]["requestId"]

            def _body_ready() -> bool:
                got = service.web_network_get(session_id, data_req_id)
                return got.ok and "gate" in str(got.data.get("body", ""))

            _poll(_body_ready, what="the /data.json response body")
            body = service.web_network_get(session_id, data_req_id)
            assert body.ok, body.error
            assert '"gate": "ok"' in body.data["body"]

            # The external script must be listed and its source fetchable, with
            # the marker only present in the real file proving it is the source.
            scripts = service.web_scripts(session_id, limit=1000)
            assert scripts.ok, scripts.error
            app_scripts = [s for s in scripts.data["scripts"] if s["url"].endswith("/app.js")]
            assert app_scripts, "the external app.js script must be parsed and listed"
            source = service.web_script_source(session_id, app_scripts[0]["scriptId"])
            assert source.ok, source.error
            assert _MARKER in source.data["source"]

            # The page instantiates a WASM module; CDP parses it as a WebAssembly
            # script, so web.wasm_list must surface it.
            def _wasm_listed() -> bool:
                listed = service.web_wasm_list(session_id)
                return listed.ok and listed.data["total"] >= 1

            _poll(_wasm_listed, what="the instantiated WASM module")
            wasm = service.web_wasm_list(session_id)
            assert wasm.data["scripts"], "the WASM module the page instantiated must be listed"
            assert all(
                str(s["language"]).lower() == "webassembly" for s in wasm.data["scripts"]
            )

            # A screenshot and a HAR export round out the capture surface.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            assert shot.data["size"] > 0

            har = service.web_har_export(session_id)
            assert har.ok, har.error
            assert har.data["entry_count"] >= 3

            closed = service.web_close(session_id)
            assert closed.ok, closed.error
    finally:
        service.close_all()
