"""web.navigate must leave the same session-timeline trail its siblings do.

web.open, web.close, web.screenshot and web.har.export each append a timeline
entry, but web.navigate -- the state-changing call that decides which page every
later read (console, DOM snapshot, network, scripts) actually describes -- went
through the generic wrapper and recorded nothing. A session timeline that omits
the navigations could not be reconstructed: an auditor saw the browser open and
then a burst of reads with no record of where it had been pointed.

The entry records the resolved landing url (page.url after redirects), not the
requested one, so a navigation that redirected is logged as where it ended up.
A navigation that fails records nothing, the same as every other tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeWeb:
    """WebBackend stand-in: navigate returns a landing url, or raises."""

    def __init__(self, *, landing_url: str | None = "https://example.com/landing",
                 error: WebError | None = None) -> None:
        self.navigated: list[str] = []
        self._landing_url = landing_url
        self._error = error

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        self.navigated.append(url)
        if self._error is not None:
            raise self._error
        return {"url": self._landing_url, "title": "Example", "status": 200}

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


def _navigate_events(service: AnalysisService, session_id: str) -> list[JsonObject]:
    listed = service.timeline_list(session_id)
    assert listed.ok and listed.data is not None, listed.error
    return [e for e in listed.data["events"] if e.get("event") == "web.navigate"]


def test_navigate_records_the_landing_url_on_the_timeline(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeWeb(landing_url="https://example.com/after-redirect")
        service._web_backend = fake  # type: ignore[assignment]

        result = service.web_navigate(session_id, "https://example.com/start")
        assert result.ok, result.error
        assert fake.navigated == ["https://example.com/start"]

        events = _navigate_events(service, session_id)
        assert len(events) == 1, events
        entry = events[0]
        assert entry["message"] == "browser navigated"
        # The resolved landing url is logged, not the requested one, so a
        # redirect is recorded as where the browser actually ended up.
        assert entry["details"]["url"] == "https://example.com/after-redirect"
    finally:
        service.close_all()


def test_a_failed_navigation_records_nothing(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeWeb(error=WebError("backend_error", "navigation failed"))
        service._web_backend = fake  # type: ignore[assignment]

        result = service.web_navigate(session_id, "https://example.com/dead")
        assert not result.ok
        assert result.error is not None

        assert _navigate_events(service, session_id) == [], (
            "a navigation that failed must not leave a 'browser navigated' entry"
        )
    finally:
        service.close_all()
