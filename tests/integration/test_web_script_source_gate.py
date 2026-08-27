"""Live gate for web.script_source over the Debugger domain (JS branch).

The wasm gate covers script_source's WebAssembly branch, and the CDP gate reads
response bodies through network_get (the Network domain). Neither exercises what
script_source is actually for: handing back the source V8 parsed for a script,
including code that has no network resource at all. This gate eval()s a string
assembled at runtime -- so the contiguous marker never appears in the served
HTML -- and asserts script_source recovers that parsed source while network_get
on the document cannot, because there is no script resource to fetch.
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

# Assembled at runtime from parts, so the contiguous form exists only in the
# source V8 parses for the eval'd script -- never in the HTML the origin serves.
_MARKER = "w3b-evalsrc-4d21"
_PAGE = (
    "<!doctype html><html><head><title>src-gate</title><script>"
    "var parts=['w3b','evalsrc','4d21'];"
    "var code=\"window.__M='\"+parts.join('-')+\"';console.log('SRC_MARKER='+window.__M);\";"
    "eval(code);"
    "</script></head><body><h1>script source gate</h1></body></html>"
)


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        body = _PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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


def _find_marked_script(backend: WebBackend, tmp: Path) -> tuple[dict, dict] | None:
    """Return the (summary, source) of the script whose source holds the marker.

    scriptParsed for the eval'd script may land a beat after the console line,
    so this is polled by the caller. Every candidate is fetched and matched on
    the assembled marker, which only the eval'd script's source can contain.
    """
    for summary in backend.scripts("s")["scripts"]:
        try:
            source = backend.script_source("s", str(summary["scriptId"]), tmp)
        except WebError:
            continue
        if _MARKER in str(source.get("source", "")):
            return summary, source
    return None


@pytest.mark.integration
def test_web_script_source_recovers_evald_source_network_get_cannot(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — script_source Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    url = f"http://127.0.0.1:{port}/page"
    try:
        try:
            opened = backend.open("s", url, headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        assert opened["opened"] is True

        found = None
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and found is None:
            found = _find_marked_script(backend, tmp_path / "artifacts")
            if found is None:
                time.sleep(0.1)
        assert found is not None, backend.scripts("s")

        summary, source = found
        # The JS branch: real source text inlined, not the wasm .wasm-spill path.
        assert _MARKER in source["source"], source
        assert source.get("wasm") is not True
        assert "source_path" not in source, source
        assert source["truncated"] is False
        assert source["bytes"] > 0
        # It came from eval, not a fetched file: its scriptParsed url is not a
        # script resource on the wire.
        assert not str(summary.get("url", "")).endswith(".js"), summary

        # The script executed -- the console carries the assembled marker.
        console = backend.console("s", limit=200)
        assert any(_MARKER in str(item.get("text")) for item in console["console"]), console

        # network_get fundamentally cannot reach this: there is no script
        # resource, and the served document never contained the contiguous
        # marker (only the parts it was built from).
        listed = backend.network_list("s")["requests"]
        assert all(str(r.get("resourceType")).lower() != "script" for r in listed), listed
        doc = next(r for r in listed if str(r["url"]).endswith("/page"))
        detail = backend.network_get("s", str(doc["requestId"]), tmp_path / "artifacts")
        doc_body = str(detail.get("body", ""))
        assert "w3b" in doc_body, "sanity: the served document should be captured"
        assert _MARKER not in doc_body, "marker must exist only in the parsed script source"
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
