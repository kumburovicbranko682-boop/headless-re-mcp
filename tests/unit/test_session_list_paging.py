"""session.list returned every in-process session, including all the open ones."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

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


@pytest.mark.parametrize(
    ("offset", "limit"),
    [
        (None, 10),  # JSON null: int(None) raised an uncaught TypeError
        ([1], 10),  # a list is not a page coordinate
        (0, {"a": 1}),  # nor is an object
        ("abc", 10),  # non-numeric string raised an uncaught ValueError
        (0, "abc"),
    ],
)
def test_session_list_refuses_an_unreadable_page_argument(
    tmp_path: Path, offset: object, limit: object
) -> None:
    """A malformed offset/limit is the caller's mistake, not an escaped exception.

    session.list is the one meta listing whose paging lives in the service
    rather than the store, and its int() calls had no envelope: the MCP path is
    pydantic-typed, but the agent transport binds offset/limit straight from
    model output, so a JSON null or object raised a raw TypeError out of the
    service method -- not even the internal_error Result its store-backed
    siblings returned -- and a non-numeric string raised a raw ValueError. Both
    must come back as an invalid_request Result instead.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        result = service.list_sessions(offset=cast(Any, offset), limit=cast(Any, limit))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_session_list_still_takes_what_int_already_accepted(tmp_path: Path) -> None:
    """The refusal must not tighten the page arguments int() already coerced.

    Numeric strings, floats and negative offsets all worked before the guard
    (int() coerces the first two, max(0, ...) floors the third), and
    limit=None stays the unpaged reply for the web console.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        for index in range(3):
            created = service.create_session(
                f"https://example.invalid/{index}", target="web"
            )
            assert created.ok is True

        coerced = service.list_sessions(offset=cast(Any, "1"), limit=cast(Any, 2.9))
        assert coerced.ok and coerced.data is not None
        assert coerced.data["offset"] == 1
        assert coerced.data["count"] == 2

        floored = service.list_sessions(offset=-5, limit=None)
        assert floored.ok and floored.data is not None
        assert floored.data["offset"] == 0
        assert floored.data["count"] == 3
    finally:
        service.close_all()
