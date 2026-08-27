"""Closing a session must release its browser and its proxy port.

close_session tears down the per-session web browser (a real Chromium process)
and stops the per-session interception proxy (which holds a bound listen port)
outside the service lock. Both calls are unconditional -- they no-op when nothing
was started -- so a session that ever opened a browser or a proxy gets them
reclaimed on close. Nothing pinned this at the close_session level: the teardown
has churned (it was moved out from under the lock so a slow browser close would
not freeze other sessions), and a refactor that dropped or short-circuited it
would leak a Chromium process and a bound port on every close -- an unattended
server bleeds both until it dies.

These use spy backends so the invariant holds without Playwright or mitmproxy
installed: what is pinned is that close_session drives each backend's per-session
release with the right session id, and only that session's.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _SpyWeb:
    def __init__(self) -> None:
        self.closed: list[str] = []
        self.close_all_called = 0

    def close(self, session_id: str) -> dict[str, Any]:
        self.closed.append(session_id)
        return {"closed": False, "note": "nothing was open"}

    def close_all(self) -> None:
        self.close_all_called += 1


class _SpyProxy:
    def __init__(self) -> None:
        self.stopped: list[str] = []
        self.close_all_called = 0

    def stop(self, session_id: str) -> dict[str, Any]:
        self.stopped.append(session_id)
        return {"stopped": False, "note": "no proxy was running"}

    def close_all(self) -> None:
        self.close_all_called += 1


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


def test_close_session_releases_the_browser_and_the_proxy_for_that_session(
    tmp_path: Path,
) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    web = _SpyWeb()
    proxy = _SpyProxy()
    service._web_backend = web  # type: ignore[assignment]
    service._proxy_backend = proxy  # type: ignore[assignment]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        # The browser and the proxy for exactly this session were released --
        # and only this session's, not a blanket close_all.
        assert web.closed == [session_id]
        assert proxy.stopped == [session_id]
        assert web.close_all_called == 0
        assert proxy.close_all_called == 0
    finally:
        service.close_all()


def test_close_session_still_releases_web_and_proxy_when_teardown_reports_nothing(
    tmp_path: Path,
) -> None:
    """The release is unconditional, so a never-opened session still drives it.

    The point of pinning this is the ordering guarantee: the browser/proxy
    teardown must run on the close path regardless of whether anything was
    started, so a later 'this session had a browser' can never be missed. A
    backend that answers 'nothing was open' must not make close skip the call.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    web = _SpyWeb()
    proxy = _SpyProxy()
    service._web_backend = web  # type: ignore[assignment]
    service._proxy_backend = proxy  # type: ignore[assignment]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        service.close_session(session_id)
        assert session_id in web.closed
        assert session_id in proxy.stopped
    finally:
        service.close_all()
