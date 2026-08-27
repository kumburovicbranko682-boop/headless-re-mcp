"""Web capture live gate: real network/script/console extraction from a page.

The browser lifecycle gate proves a session opens and closes cleanly, but the
actual point of the web line -- capturing what a page does -- had no live
coverage: nothing ever asserted that ``network_list`` records the requests a
real navigation makes, that ``network_get`` reads a response body back through
CDP, that ``scripts`` sees an external script and ``script_source`` returns its
real source, or that ``console`` captures a page's log. Those four (plus
``dom_snapshot``) are the web-RE data-extraction pipeline, and they only ever
ran against mocks.

The fixture is a throwaway localhost HTTP server, so the whole capture runs for
real with no external network: the page pulls an external script and issues a
fetch, and the gate then reads all of it back through the backend the tools use.

Skip != pass: the gate skips with a reason when playwright or its chromium is
absent (or chromium cannot launch in this sandbox). CI installs both, so a skip
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

from headless_re_mcp.backends.web import WebBackend, WebError

# Named members so the assertions prove real recovery (a specific function in the
# script's source, a specific marker in the fetched body), not merely non-empty.
_APP_JS = (
    b"function secretAdder(a, b) { return a + b; }\n"
    b"console.log('gate-marker ' + secretAdder(2, 5));\n"
)
_DATA_JSON = b'{"marker": "GATE_DATA_7"}'
_INDEX_HTML = b"""<!doctype html>
<html><head><title>capture-gate</title></head>
<body><h1>hello</h1>
<script src="/app.js"></script>
<script>
fetch('/data.json')
  .then(r => r.json())
  .then(d => console.log('fetched:' + d.marker));
</script>
</body></html>"""

_ROUTES: dict[str, tuple[bytes, str]] = {
    "/": (_INDEX_HTML, "text/html"),
    "/app.js": (_APP_JS, "application/javascript"),
    "/data.json": (_DATA_JSON, "application/json"),
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
def test_web_backend_captures_network_scripts_and_console(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web capture Gate not run (skip != pass)")

    backend = WebBackend()
    with _local_site() as url:
        try:
            backend.open("capture", url, headless=True, timeout=30.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        try:
            # The fetch is async, so wait until its request lands rather than
            # racing domcontentloaded.
            def _fetch_captured() -> bool:
                requests = backend.network_list("capture", limit=100)["requests"]
                return any("/data.json" in str(r.get("url")) for r in requests)

            assert _wait_for(_fetch_captured), "the fetch request was never captured"

            requests = backend.network_list("capture", limit=100)["requests"]
            paths = {str(r.get("url")).rsplit("/", 1)[-1] or "index" for r in requests}
            # The document, the external script and the fetch are three distinct
            # requests a real navigation makes; all must be recorded.
            assert {"app.js", "data.json"} <= paths
            assert any(str(r.get("url")).endswith("/") for r in requests), "document not recorded"

            # network_get must read the real response body back through CDP.
            data_req = next(r for r in requests if "/data.json" in str(r.get("url")))
            fetched = backend.network_get("capture", str(data_req["requestId"]), tmp_path)
            assert "GATE_DATA_7" in fetched["body"]

            # scripts must see the external script; script_source must return its
            # actual source, not a stub.
            scripts = backend.scripts("capture", limit=200)["scripts"]
            app_script = next((s for s in scripts if "app.js" in str(s.get("url"))), None)
            assert app_script is not None, "the external script was not captured"
            source = backend.script_source("capture", str(app_script["scriptId"]), tmp_path)
            assert "secretAdder" in source["source"]

            # console must capture both the script's log and the fetch callback's.
            assert _wait_for(
                lambda: any(
                    "fetched:GATE_DATA_7" in str(c.get("text"))
                    for c in backend.console("capture", limit=200)["console"]
                )
            ), "the fetch-callback console log was never captured"
            texts = [str(c.get("text")) for c in backend.console("capture", limit=200)["console"]]
            assert any("gate-marker 7" in t for t in texts)

            # dom_snapshot must reflect the live document.
            assert backend.dom_snapshot("capture")["title"] == "capture-gate"
        finally:
            backend.close_all()
