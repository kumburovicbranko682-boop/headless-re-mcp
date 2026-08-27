"""web.network.list live gate: a real failed subresource load is marked failed.

A request that never gets a response fires CDP's ``Network.loadingFailed``, not
``Network.responseReceived``, and the reason (``net::ERR_NAME_NOT_RESOLVED``, a
``blockedReason``) appears only there. The handler used to ignore that event, so
the request entry kept its null status forever and a failed load -- often the
finding in an RE session: a beacon the page could not reach, a tracker the
browser blocked -- read like a request still in flight. The backend now marks
the entry ``failed: true`` with ``error_text``.

Every unit test drives the CDP handlers with hand-written events, so only a real
Chromium proves that a genuine failed navigation produces a ``loadingFailed`` the
backend surfaces. The page requests a subresource from a ``.invalid`` host
(RFC 2606 guarantees it never resolves), so the failure happens for real with no
external network: DNS resolution fails immediately and offline.

Skip != pass: the gate skips with a reason only when playwright or its Chromium
is absent. CI installs both, so a skip there is a genuine regression rather than
a bare machine.
"""

from __future__ import annotations

import time

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

# RFC 2606 reserves .invalid; the browser fails to resolve it immediately and
# offline, so the subresource load fails for real without any network.
_BAD_HOST = "nonexistent-re-mcp-gate.invalid"
_PAGE = (
    "data:text/html,"
    "<html><body>gate"
    f"<img src='http://{_BAD_HOST}/x.png'>"
    "</body></html>"
)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_a_failed_subresource_is_marked_failed_with_its_error() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — loading-failed Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_PAGE, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, url=_PAGE, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # The image load fails asynchronously; give CDP a moment to deliver
            # loadingFailed after domcontentloaded returned.
            failed_row = None
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                listing = service.web_network_list(session_id, limit=1000)
                assert listing.ok, listing.error
                for row in listing.data["requests"]:
                    if _BAD_HOST in str(row.get("url")) and row.get("failed"):
                        failed_row = row
                        break
                if failed_row is not None:
                    break
                time.sleep(0.3)

            assert failed_row is not None, "the failed .invalid request was never marked failed"
            # The fix: the entry says it failed and why, and its status stays null.
            assert failed_row["failed"] is True
            assert str(failed_row["error_text"]).startswith("net::"), failed_row["error_text"]
            assert failed_row["status"] is None
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
