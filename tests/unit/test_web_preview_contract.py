"""web.preview is a stable, unregistered inspect shot -- unlike web.screenshot.

web.preview exists to be called repeatedly (a cheap "what does the page look
like now"), so it overwrites one stable preview.png and, deliberately, does not
register an artifact. web.screenshot is the opposite: a uuid-named file that is
registered for later retrieval. Only the path-safety guard was pinned; the
behavioural contract that keeps preview from leaking a fresh artifact on every
call (the way screenshot legitimately does) was not. A regression that gave
preview a uuid name or ran it through _register_capture would turn a viewport
poll into unbounded artifact growth with nothing to reclaim it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeWeb:
    """WebBackend stand-in that records screenshot targets, opens no browser."""

    def __init__(self) -> None:
        self.shots: list[tuple[str, Path, bool]] = []

    def screenshot(
        self, session_id: str, out_path: Path, *, full_page: bool = False
    ) -> JsonObject:
        self.shots.append((session_id, out_path, full_page))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"\x89PNG\r\n\x1a\n")
        return {"path": str(out_path), "full_page": full_page}

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


def test_web_preview_overwrites_one_stable_unregistered_png(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeWeb()
        service._web_backend = fake  # type: ignore[assignment]

        first = service.web_preview(session_id)
        second = service.web_preview(session_id)

        assert first.ok, first.error
        assert second.ok, second.error
        assert first.meta.get("backend") == "web"

        # Both previews are viewport-only and land on the same stable file, so a
        # loop that polls the page cannot accumulate images.
        assert [full_page for _, _, full_page in fake.shots] == [False, False]
        targets = {out for _, out, _ in fake.shots}
        assert len(targets) == 1
        only = next(iter(targets))
        assert only.name == "preview.png"

        # Not an artifact: preview must not mint a registered capture the way
        # web.screenshot does, or every poll would leave one behind.
        assert first.data is not None
        assert "artifact_id" not in first.data
        records = service.artifacts_list(session_id)
        assert records.ok, records.error
        assert records.data is not None
        assert records.data.get("artifacts") == []
    finally:
        service.close_all()
