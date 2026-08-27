"""sessions.unclean must page a crash-marked batch in a stable, total order."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.core import repository as repository_module
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.store import sqlite_store


class _FrozenClock:
    """A ``datetime`` stand-in whose ``now`` never advances.

    On startup ``mark_unclean_open_sessions`` rewrites every still-open
    session's ``updated_at`` in a single UPDATE, so after a crash the whole
    unclean list shares one timestamp. Creating the rows under a frozen clock
    reproduces that mass collision rather than relying on a coarse wall clock.
    """

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self, tz: object = None) -> datetime:
        return self._moment


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_list_unclean_sessions_breaks_updated_at_ties_by_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    """A batch sharing one updated_at must page as a single stable, total order.

    sessions.unclean is the tool a caller reaches for right after a crash, and
    that is exactly when every row shares the one timestamp the startup mark
    stamped them with. Ordering by updated_at alone then leaves the batch in an
    unspecified order (sqlite), and since each page is its own LIMIT/OFFSET
    query, a session could drop out of every page or appear in two. The reader
    must break ties by id -- the total order the closed-session trim already
    uses -- so a full read and a paged read agree.
    """
    frozen = _FrozenClock(datetime(2020, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(sqlite_store, "datetime", frozen)
    monkeypatch.setattr(repository_module, "datetime", frozen)

    repository = repository_type(tmp_path / "artifacts")
    # A fixed shuffle, not random uuids, so the check is deterministic: the
    # insertion order is not the id-descending order, so a reader that returned
    # insertion order (sqlite's for tied rows, and a stable sort's) is caught.
    ids = ["s3", "s1", "s5", "s0", "s4", "s2"]
    for session_id in ids:
        repository.note_session_created(
            "b", _success({"session": {"id": session_id, "state": "created"}})
        )
    expected = sorted(ids, reverse=True)
    assert ids != expected

    full, total = repository.list_unclean_sessions(limit=10)
    assert total == len(ids)
    assert [row["id"] for row in full] == expected

    paged: list[str] = []
    for start in range(0, len(ids), 2):
        rows, _ = repository.list_unclean_sessions(offset=start, limit=2)
        paged.extend(row["id"] for row in rows)
    assert paged == expected
