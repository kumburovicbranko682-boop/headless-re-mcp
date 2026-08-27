"""web.open resolves its target by session kind, and refuses a bare non-web open.

A web session is created on a URL, which it keeps as its locator, so opening it
with no explicit url reuses that URL. A non-web session (a PE or APK) is created
on a *file*, whose path is its locator -- never something a browser can
navigate. The service used to fall back to the locator for any session, so a
bare ``web.open`` on a PE/APK session handed that file path to the browser: it
surfaced as an opaque ``backend_error`` (page.goto refusing a non-URL), or, on a
host without Playwright, as a misleading ``capability_unavailable`` from the
backend's availability check -- when the real answer is "give me a url".

Pin the contract the guard's own message promises: a non-web session with no
url fails closed as ``invalid_params`` before the backend is touched at all,
while an explicit url is used verbatim (never silently swapped for the locator),
and a web session still reuses its locator when the caller omits the url.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, TargetKind
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _RecordingWeb:
    """A WebBackend stand-in that records the target every open() receives."""

    def __init__(self) -> None:
        self.opened: list[str] = []

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        self.opened.append(url)
        return {"opened": True, "url": url or "https://app/", "title": "T", "headless": headless}

    def close(self, session_id: str) -> JsonObject:
        return {"closed": True}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path) -> tuple[AnalysisService, _RecordingWeb]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _RecordingWeb()
    service._web_backend = fake  # type: ignore[assignment]
    return service, fake


def _adopt(service: AnalysisService, session: Session) -> str:
    return service.registry.adopt(session).id


def test_a_bare_open_on_a_non_web_session_fails_closed_before_the_backend(
    tmp_path: Path,
) -> None:
    """A PE session with no url is invalid_params, and the browser is untouched."""
    service, fake = _service(tmp_path)
    try:
        sid = _adopt(
            service, Session(target=TargetKind.PE, locator="/nonexistent/app.exe")
        )
        result = service.web_open(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        # The refusal lands at the service layer: the file-path locator never
        # reached the backend as a would-be navigation target.
        assert fake.opened == []
    finally:
        service.close_all()


def test_a_non_web_session_uses_the_explicit_url_not_the_file_locator(
    tmp_path: Path,
) -> None:
    """An explicit url on a PE session is what opens -- never its .exe locator."""
    service, fake = _service(tmp_path)
    try:
        sid = _adopt(
            service, Session(target=TargetKind.PE, locator="/nonexistent/app.exe")
        )
        result = service.web_open(sid, url="https://example.com/docs")
        assert result.ok is True, result.error
        assert fake.opened == ["https://example.com/docs"]
    finally:
        service.close_all()


def test_a_web_session_still_reuses_its_locator_when_the_url_is_omitted(
    tmp_path: Path,
) -> None:
    """The web-session fallback is preserved: an omitted url opens the locator."""
    service, fake = _service(tmp_path)
    try:
        sid = _adopt(
            service, Session(target=TargetKind.WEB, locator="https://example.com/app")
        )
        result = service.web_open(sid)
        assert result.ok is True, result.error
        assert fake.opened == ["https://example.com/app"]
    finally:
        service.close_all()


def test_a_web_session_prefers_an_explicit_url_over_its_locator(tmp_path: Path) -> None:
    """An explicit url overrides the stored locator for a web session too."""
    service, fake = _service(tmp_path)
    try:
        sid = _adopt(
            service, Session(target=TargetKind.WEB, locator="https://example.com/app")
        )
        result = service.web_open(sid, url="https://example.com/other")
        assert result.ok is True, result.error
        assert fake.opened == ["https://example.com/other"]
    finally:
        service.close_all()
