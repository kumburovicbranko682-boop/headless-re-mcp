"""Live web gate: network_get returns each resource's own response body.

The CDP capture gate asserts that requests appear in network_list, but never
pulls a body back, so Network.getResponseBody -- the point of network_get -- is
untested end to end. The script_source gate covers the negative direction (a
marker reachable only through the debugger, not through network_get of the
document). This gate covers the positive: a page that loads a linked script and
fetches a JSON resource, and network_get hands back each resource's exact bytes,
keyed by request id, distinct from the document's own body. It also pins the
unknown-id contract. skip != pass when playwright/chromium is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError

_MARK_JS = "net-get-js-marker-7f3a"
_MARK_DOC = "net-get-doc-marker-9c1b"
_MARK_JSON = "net-get-json-marker-2e8d"

_APP_JS = f"console.log('{_MARK_JS}');"
_DATA_JSON = f'{{"marker":"{_MARK_JSON}"}}'
_PAGE = (
    "<!doctype html><html><head><title>netget</title>"
    '<script src="/app.js"></script></head>'
    f"<body><h1>{_MARK_DOC}</h1>"
    "<script>fetch('/data.json').then(r=>r.text())"
    ".then(t=>console.log('FETCHED='+t.length));</script>"
    "</body></html>"
)
_PAGES: dict[str, tuple[str, str]] = {
    "/page": (_PAGE, "text/html; charset=utf-8"),
    "/app.js": (_APP_JS, "application/javascript; charset=utf-8"),
    "/data.json": (_DATA_JSON, "application/json; charset=utf-8"),
}


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        body, ctype = _PAGES.get(self.path, ("not found", "text/plain; charset=utf-8"))
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

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


def _await_captured(backend: WebBackend, leaves: tuple[str, ...]) -> dict[str, dict]:
    """Poll network_list until every leaf is captured with a 200 response."""
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        found: dict[str, dict] = {}
        for req in backend.network_list("web")["requests"]:
            for leaf in leaves:
                if str(req.get("url")).endswith(leaf) and req.get("status") == 200:
                    found[leaf] = req
        if len(found) == len(leaves):
            return found
        time.sleep(0.1)
    return found


@pytest.mark.integration
def test_web_network_get_returns_each_resources_body(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web network_get Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    try:
        try:
            backend.open("web", f"http://127.0.0.1:{port}/page", headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        leaves = ("/page", "/app.js", "/data.json")
        captured = _await_captured(backend, leaves)
        assert set(captured) == set(leaves), captured

        art = tmp_path / "artifacts"

        def _body(req: dict) -> dict:
            # getResponseBody can briefly race a just-finished load; retry.
            detail = backend.network_get("web", str(req["requestId"]), art)
            for _ in range(20):
                if not detail.get("body_error"):
                    break
                time.sleep(0.1)
                detail = backend.network_get("web", str(req["requestId"]), art)
            assert not detail.get("body_error"), detail
            return detail

        # The linked script: network_get returns its exact source, not base64,
        # small enough to inline (no spill).
        js = _body(captured["/app.js"])
        assert js["base64_encoded"] is False, js
        assert js["body_truncated"] is False, js
        assert "body_path" not in js, js
        assert js["body"] == _APP_JS, js
        assert _MARK_JS in js["body"], js
        assert "javascript" in str(captured["/app.js"]["mimeType"]).lower()

        # The fetched JSON resource: its own body, keyed by its own request id.
        data = _body(captured["/data.json"])
        assert _MARK_JSON in data["body"], data
        assert "json" in str(captured["/data.json"]["mimeType"]).lower()

        # The document: HTML body carrying the page-only marker.
        doc = _body(captured["/page"])
        assert _MARK_DOC in doc["body"], doc
        assert "html" in str(captured["/page"]["mimeType"]).lower()

        # network_get is per-resource, not per-page: the script's and the JSON's
        # markers live in their own bodies and never in the document's.
        assert _MARK_JS not in doc["body"], doc
        assert _MARK_JSON not in doc["body"], doc

        # Unknown request id fails closed with not_found rather than leaking.
        with pytest.raises(WebError) as caught:
            backend.network_get("web", "no-such-request-id", art)
        assert caught.value.code == "not_found"
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
