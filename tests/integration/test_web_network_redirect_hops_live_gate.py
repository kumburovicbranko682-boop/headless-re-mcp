"""web.network.list live gate: a real redirect chain is listed hop by hop.

CDP reuses one requestId for a whole redirect chain: every hop after the first
arrives as another ``Network.requestWillBeSent`` for the same id, carrying the
finished hop's 3xx status and URL only in ``redirectResponse`` -- a redirect
never fires ``Network.responseReceived``. The old handler ignored that field
and overwrote the entry keyed by requestId, so ``web.network.list`` showed only
the final destination: the 302/307 hops that decide where traffic really goes
-- exactly what a login-flow or SSO analysis needs to read -- silently
vanished, and nothing said a redirect ever happened.

Every unit test drives the CDP handlers with hand-written events, so only a
real Chromium proves that genuine ``redirectResponse`` payloads are captured
once real navigation crosses the wire. The fixture is a throwaway localhost
origin whose ``/login`` answers 302 to ``/step`` and ``/step`` answers 307 to
``/home``; the browser navigates to ``/login`` and the gate asserts the listing
holds all three hops in order with their statuses and forwarding targets.

Skip != pass: the gate skips with a reason only when playwright or its
Chromium is absent. CI installs both, so a skip there is a genuine regression
rather than a bare machine.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_BODY = b"<html><title>landed</title><body>home</body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass

    def do_GET(self) -> None:
        if self.path == "/login":
            self.send_response(302)
            self.send_header("Location", "/step")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/step":
            self.send_response(307)
            self.send_header("Location", "/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/home":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_BODY)))
            self.end_headers()
            self.wfile.write(_BODY)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@contextmanager
def _redirecting_origin() -> Iterator[str]:
    server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_network_list_shows_every_hop_of_a_real_redirect_chain() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — redirect-hops Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        with _redirecting_origin() as origin:
            created = service.create_session(f"{origin}/login", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(
                session_id, url=f"{origin}/login", headless=True, timeout=30.0
            )
            if not opened.ok:
                pytest.skip(
                    f"chromium could not launch (browser not installed?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # Navigation followed the chain: the page landed on /home.
                assert str(opened.data["url"]).endswith("/home"), opened.data

                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                by_url = {
                    str(row["url"]): row
                    for row in listing.data["requests"]
                    if str(row["url"]).startswith(origin)
                }

                # The fix: both 3xx hops are present with their real statuses
                # and forwarding targets, not collapsed into the final hop.
                login = by_url[f"{origin}/login"]
                assert login["status"] == 302
                assert login["redirect"] is True
                assert str(login["redirected_to"]).endswith("/step")

                step = by_url[f"{origin}/step"]
                assert step["status"] == 307
                assert step["redirect"] is True
                assert str(step["redirected_to"]).endswith("/home")

                home = by_url[f"{origin}/home"]
                assert home["status"] == 200
                assert "redirect" not in home
                assert "redirected_to" not in home

                # All three hops share one CDP chain: the synthetic hop ids are
                # derived from the final hop's requestId, and wire order holds.
                assert str(login["requestId"]).startswith(f"{home['requestId']}:redirect:")
                assert str(step["requestId"]).startswith(f"{home['requestId']}:redirect:")
                ordered = [
                    str(row["url"])
                    for row in listing.data["requests"]
                    if str(row["url"]).startswith(origin)
                ]
                assert ordered == [f"{origin}/login", f"{origin}/step", f"{origin}/home"]
            finally:
                service.web_close(session_id)
    finally:
        service.close_all()
