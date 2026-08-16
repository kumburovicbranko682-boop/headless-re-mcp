"""session.list returned every in-process session, including all the open ones."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def test_session_list_pages_and_says_how_much_it_left_behind(tmp_path: Path) -> None:
    """3000 open sessions encoded to 878 KiB; a page of 100 is 29 KiB.

    CHANGELOG called sessions.unclean the only unpaged list. session.list
    was the other one: closed sessions are capped, open ones are not.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        for index in range(25):
            created = service.create_session(
                f"https://example.invalid/{index}", target="web"
            )
            assert created.ok is True

        page = service.list_sessions(limit=10)
        assert page.ok and page.data is not None
        assert page.data["count"] == 10
        assert page.data["total"] == 25
        assert page.data["offset"] == 0
        assert page.data["has_more"] is True

        tail = service.list_sessions(offset=20, limit=10)
        assert tail.data is not None
        assert tail.data["count"] == 5
        assert tail.data["has_more"] is False
        first_ids = {item["id"] for item in page.data["sessions"]}
        tail_ids = {item["id"] for item in tail.data["sessions"]}
        assert first_ids & tail_ids == set()

        whole = service.list_sessions()
        assert whole.data is not None
        assert whole.data["count"] == 25
        assert whole.data["has_more"] is False
    finally:
        service.close_all()
