"""Web CDP redirect gate: a redirect chain keeps its earlier hops.

CDP reuses one requestId across an HTTP redirect chain and delivers each hop's
status in the *next* ``Network.requestWillBeSent`` event's ``redirectResponse``
field -- there is never a ``responseReceived`` for a URL that redirected away.
The capture used to overwrite the entry with the redirected-to URL and ignore
``redirectResponse`` entirely, so ``/start -(302)-> /end (200)`` collapsed to a
single ``/end (200)`` row: a reader could not tell a redirect had happened, nor
what status it returned. A fake-based test cannot catch this -- it is exactly
the CDP event ordering that only a real browser produces.

This gate stands up a throwaway HTTP server whose ``/start`` answers 302 with
``Location: /end`` and whose ``/end`` answers 200, opens ``/start`` through the
real CDP browser, and pins that the captured request ends at ``/end`` with
status 200 while carrying a ``redirects`` trail whose hop is ``/start`` at 302.
Skips (skip != pass) when Playwright / Chromium is not installed.
"""

from __future__ import annotations

import contextlib
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_START = "/start"
_END = "/end"
_END_PAGE = b"<!doctype html><html><head><title>redirect-end</title></head><body>end</body></html>"


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?", 1)[0]
        if path == _START:
            self.send_response(302)
            self.send_header("Location", _END)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = _END_PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass  # keep the test output quiet


@pytest.mark.integration
def test_web_redirect_chain_records_earlier_hops() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web redirect Gate not run (skip != pass)")

    origin = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = origin.server_address[1]
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    service = AnalysisService()
    session_id: str | None = None
    try:
        created = service.create_session(f"http://127.0.0.1:{port}{_START}", target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )

        deadline = time.monotonic() + 15.0
        final: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            listed = service.web_network_list(session_id, limit=1000)
            assert listed.ok, listed.error
            final = next(
                (
                    r
                    for r in listed.data["requests"]
                    if str(r.get("url", "")).endswith(_END)
                    and r.get("status") is not None
                    and r.get("redirects")
                ),
                None,
            )
            if final is not None:
                break
            time.sleep(0.1)

        assert final is not None, "no captured request ended at /end carrying a redirect trail"
        # The chain resolved to /end with a real 200 ...
        assert final["status"] == 200
        assert str(final["url"]).endswith(_END)
        # ... and the earlier /start hop and its 302 survived rather than being
        # overwritten into oblivion.
        trail = final["redirects"]
        assert any(
            str(hop.get("url", "")).endswith(_START) and hop.get("status") == 302 for hop in trail
        ), f"redirect trail did not record the /start 302 hop: {trail}"
    finally:
        if session_id is not None:
            with contextlib.suppress(Exception):
                service.web_close(session_id)
        origin.shutdown()
