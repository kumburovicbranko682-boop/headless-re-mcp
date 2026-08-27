"""web.open must close the browser it just launched if the session raced away.

web_open re-checks the session state after the backend has a browser up: a
concurrent session.close landing during the (up to tens of seconds) launch
would otherwise leave a headless Chromium running with no live session that
could ever web.close it -- the browser twin of the proxy.start leaked-port
rollback (test_proxy_start_race_rollback) and of the apk write-tree rollbacks
(test_apk_write_race_rollback). The rollback branch in service_web.web_open
had no coverage in either direction: neither "the raced open closes the
browser" nor "a normal open does not".

A fake WebBackend records open/close and, in the racing variant, drives the
session to FAILED (allowed from created) as open's side effect -- the
deterministic version of the concurrent close.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeWeb:
    """WebBackend stand-in: records open/close, launches no real browser."""

    def __init__(self, *, on_open: Any = None) -> None:
        self.opened: list[str] = []
        self.closed: list[str] = []
        self._on_open = on_open

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        self.opened.append(session_id)
        if self._on_open is not None:
            self._on_open(session_id)
        return {"url": url or "about:blank", "title": "", "headless": headless}

    def close(self, session_id: str) -> JsonObject:
        self.closed.append(session_id)
        return {"closed": True}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def test_web_open_succeeds_without_touching_close_when_the_session_stays_live(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeWeb()
        service._web_backend = fake  # type: ignore[assignment]

        result = service.web_open(session_id)

        assert result.ok, result.error
        assert result.data is not None
        assert result.data["url"] == "https://example.com/app"
        assert fake.opened == [session_id]
        assert fake.closed == [], "a live session must not trigger the rollback close"
    finally:
        service.close_all()


def test_web_open_closes_the_browser_when_the_session_races_to_terminal(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)

        def _fail_mid_open(sid: str) -> None:
            service.registry.transition(sid, SessionState.FAILED)

        fake = _FakeWeb(on_open=_fail_mid_open)
        service._web_backend = fake  # type: ignore[assignment]

        result = service.web_open(session_id)

        assert not result.ok, "a session that went terminal mid-open must not report ok"
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert fake.opened == [session_id]
        assert fake.closed == [session_id], (
            "the just-launched browser must be closed; leaving it up is a headless "
            "Chromium no live session can ever web.close"
        )
    finally:
        service.close_all()


def test_web_open_refuses_a_session_already_terminal_before_launching(
    tmp_path: Path,
) -> None:
    """The pre-check half: an already-terminal session never reaches the
    backend, so no browser is launched at all."""
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service.registry.transition(session_id, SessionState.FAILED)

        fake = _FakeWeb()
        service._web_backend = fake  # type: ignore[assignment]

        result = service.web_open(session_id)

        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert fake.opened == [], "a terminal session must never launch a browser"
        assert fake.closed == []
    finally:
        service.close_all()
