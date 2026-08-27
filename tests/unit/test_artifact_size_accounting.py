from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from headless_re_mcp.core import repository as repository_module
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store import sqlite_store


class _FrozenClock:
    """A ``datetime`` stand-in whose ``now`` never advances.

    Registering several rows against it stamps them all with one isoformat
    string, reproducing the created_at collision a coarse-resolution clock
    (notably Windows) produces when a caller registers a burst inside one tick.
    """

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self, tz: object = None) -> datetime:
        return self._moment


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_artifact_registration_uses_the_file_size_not_an_untrusted_hint(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    root = tmp_path / "artifacts"
    repository = repository_type(root)
    oldest = root / "oldest.bin"
    newest = root / "newest.bin"
    oldest.parent.mkdir(parents=True, exist_ok=True)
    oldest.write_bytes(b"O" * 64)
    newest.write_bytes(b"N" * 64)

    recorded = repository.register_artifact(
        session_id="session",
        kind="dump",
        path=oldest,
        sha256="0" * 64,
        source="test",
        size=1,
    )
    repository.register_artifact(
        session_id="session",
        kind="dump",
        path=newest,
        sha256="1" * 64,
        source="test",
        size=1,
    )

    assert recorded["size"] == 64
    collected = repository.gc_artifacts(max_total_bytes=64)
    assert recorded["id"] in collected["removed"]
    assert not oldest.exists()
    assert newest.is_file()


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_artifact_registration_rejects_negative_size_for_a_missing_file(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    repository = repository_type(tmp_path / "artifacts")

    with pytest.raises(ValueError, match="cannot be negative"):
        repository.register_artifact(
            session_id="session",
            kind="missing",
            path=tmp_path / "missing.bin",
            sha256="0" * 64,
            source="test",
            size=-1,
        )

    assert repository.list_artifacts()["total"] == 0


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_list_artifacts_breaks_created_at_ties_by_id_so_pages_are_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    """Artifacts sharing a created_at must page as one stable, total order.

    A coarse-resolution clock stamps several artifacts registered in one tick
    with the same isoformat string. sqlite leaves rows equal under ORDER BY in
    an unspecified order, and each page is its own LIMIT/OFFSET query, so a tied
    row could fall out of both pages or appear in both. The reader must break
    ties by id -- the same total order append_audit trims by -- so a full read
    and a paged read agree.
    """
    frozen = _FrozenClock(datetime(2020, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(sqlite_store, "datetime", frozen)
    monkeypatch.setattr(repository_module, "datetime", frozen)

    repository = repository_type(tmp_path / "artifacts")
    ids = [
        repository.register_artifact(
            session_id="s1",
            kind="dump",
            path=tmp_path / f"missing-{index}.bin",
            sha256="0" * 64,
            source="test",
            size=1,
        )["id"]
        for index in range(6)
    ]
    # The uuids are random, so a reader that returned insertion order (what
    # sqlite does for tied rows, and what a stable sort keeps) would not be
    # id-descending -- this is what fails before the tie-break.
    assert ids != sorted(ids, reverse=True)

    full = [item["id"] for item in repository.list_artifacts("s1", limit=10)["artifacts"]]
    assert full == sorted(ids, reverse=True)

    paged: list[str] = []
    for start in range(0, len(ids), 2):
        page = repository.list_artifacts("s1", offset=start, limit=2)["artifacts"]
        paged.extend(item["id"] for item in page)
    assert paged == full


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_list_audit_breaks_ties_by_id_matching_the_trim_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    """Audit entries with the same timestamp must page in the trim's total order.

    append_audit trims to the newest rows by (at, id) descending, but the reader
    ordered by at alone, so a set of same-timestamp rows could page differently
    from the way it was trimmed -- a row visible to the trim yet skipped or
    repeated by a paged read. Freeze the clock and assert the reader breaks ties
    by id too.
    """
    frozen = _FrozenClock(datetime(2020, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(sqlite_store, "datetime", frozen)
    monkeypatch.setattr(repository_module, "datetime", frozen)

    repository = repository_type(tmp_path / "artifacts")
    for index in range(6):
        repository.append_audit(
            session_id="s1",
            action=f"tool.{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    full = [item["id"] for item in repository.list_audit("s1", limit=10)["entries"]]
    assert full == sorted(full, reverse=True)

    paged: list[str] = []
    for start in range(0, 6, 2):
        page = repository.list_audit("s1", offset=start, limit=2)["entries"]
        paged.extend(item["id"] for item in page)
    assert paged == full
