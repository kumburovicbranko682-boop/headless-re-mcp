"""proxy.export_har live gate: a 3xx entry's redirectURL is the real Location.

The bug: ``har_entry`` hardcoded ``response.redirectURL`` to ``""`` for every
entry, so an exported HAR lost the redirect chain even though the proxy captures
each 3xx hop as its own flow. The HAR 1.2 spec defines ``response.redirectURL``
as the ``Location`` header value, and a consumer (Chrome DevTools "Import HAR",
Firefox) links a redirect entry to the request it points at through that field;
blanked, an imported capture cannot follow the redirects it actually recorded.

This gate drives one request through a real mitmproxy to an origin that answers
``/redirect`` with a 302 carrying an absolute ``Location`` to ``/target`` (and
follows it, exactly as a browser would, producing the final 200 flow too). It
then exports the HAR and asserts the 302 entry's ``redirectURL`` is that exact
absolute target -- proving mitmproxy captured the real header and the export
carried it, not a fabricated value -- while the plain 200 ``/target`` entry
keeps the spec's empty ``redirectURL``, proving the field is not blanket-filled.
Guarding the guard: the Location the assertion checks is a distinct URL from the
requested one, so a pass means the header round-tripped, not a coincidence.
skip != pass: it skips only when mitmproxy is genuinely absent.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.path.endswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.server.target_url)  # type: ignore[attr-defined]
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _origin() -> Iterator[tuple[str, str]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    target_url = f"http://127.0.0.1:{port}/target"
    server.target_url = target_url  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", target_url
    finally:
        server.shutdown()
        server.server_close()


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


def _get_through_proxy(url: str, proxy: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
    with opener.open(url, timeout=20.0) as response:
        response.read()


@pytest.mark.integration
def test_export_har_fills_redirect_url_from_the_captured_location(
    tmp_path: Path,
) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — HAR redirectURL Gate not run (skip != pass)")

    backend = ProxyBackend()
    proxy_port = _free_port()
    started = backend.start("har-redirect-gate", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        with _origin() as (origin, target_url):
            # Guarding the guard: the target the assertion checks is a different
            # URL from the one requested, so a pass proves the Location header
            # round-tripped rather than echoing the request URL.
            assert not target_url.endswith("/redirect")
            _get_through_proxy(f"{origin}/redirect", f"http://127.0.0.1:{proxy_port}")

            redirect_row: dict | None = None
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                for candidate in backend.flows("har-redirect-gate", offset=0, limit=50)["flows"]:
                    if str(candidate.get("url", "")).endswith("/redirect"):
                        redirect_row = candidate
                        break
                if redirect_row is not None:
                    break
                time.sleep(0.2)
            assert redirect_row is not None, "the /redirect flow never appeared"
            assert redirect_row.get("redirect_url") == target_url, redirect_row

            out = tmp_path / "capture.har"
            backend.export_har("har-redirect-gate", out)

            doc = json.loads(out.read_text(encoding="utf-8"))
            entries = {e["request"]["url"]: e for e in doc["log"]["entries"]}
            redirect_entry = next(
                e for url, e in entries.items() if url.endswith("/redirect")
            )
            assert redirect_entry["response"]["status"] == 302
            assert redirect_entry["response"]["redirectURL"] == target_url

            # The followed 200 flow must keep the spec's empty redirectURL: the
            # field is filled from a real Location, never applied blanket.
            target_entry = next(
                (e for url, e in entries.items() if url.endswith("/target")), None
            )
            assert target_entry is not None, "the followed /target flow never appeared"
            assert target_entry["response"]["status"] == 200
            assert target_entry["response"]["redirectURL"] == ""
    finally:
        backend.stop("har-redirect-gate")
