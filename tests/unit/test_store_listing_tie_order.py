"""Same-tick rows must come back in one total order from every entry point.

Every store listing sorts on a wall-clock stamp, and on Windows 3.12 the
system clock steps every ~15.6 ms, so back-to-back writes routinely share one
stamp (the audit-trim fix measured six on a single tick). Without an id
tiebreak the order among tied rows is whatever the query plan yields.
Measured on this machine before the fix: the unfiltered audit listing walks
``idx_audit_at`` and returned same-tick rows newest-inserted-first, while the
session-filtered branch sorts and returned them oldest-inserted-first -- the
same five rows in opposite orders from the two branches of one API. An OFFSET
page over a non-total order can also repeat or drop a boundary row whenever
the plan changes, and the in-memory twin's stable sort silently disagreed
with both. These pin (timestamp DESC, id DESC) as the shared total order on
both repository twins -- the same order the audit trim already uses to decide
survival -- and pin gc's newest-artifact protection to insertion order.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.core.repository as repo_module
import headless_re_mcp.core.store.sqlite_store as sqlite_store_module
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.store.sqlite_store import SessionStore
from tests.unit.test_repository_inmemory_close_trim import _created


def _freeze_clock(monkeypatch: pytest.MonkeyPatch, module: object) -> None:
    """Stamp every write identically, the way a coarse Windows tick does."""
    frozen = datetime(2024, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(module, "datetime", SimpleNamespace(now=lambda tz=UTC: frozen))


def _script_ids(monkeypatch: pytest.MonkeyPatch, module: object, ids: list[str]) -> None:
    """Hand out known row ids, deliberately not in insertion order."""
    queue = iter(ids)
    monkeypatch.setattr(module, "uuid4", lambda: SimpleNamespace(hex=next(queue)))


def _sqlite(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "meta" / "store.db")


def test_sqlite_audit_ties_return_one_order_from_both_entry_points(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The filtered and unfiltered listings disagreed on tied rows.

    Pre-fix the unfiltered branch (idx_audit_at scan) returned
    [id-e, id-b, id-m, id-a, id-c] and the filtered branch (sort plan)
    the exact reverse; both must return (at DESC, id DESC), which is also
    how the trim right above them decides what survives.
    """
    _freeze_clock(monkeypatch, sqlite_store_module)
    _script_ids(monkeypatch, sqlite_store_module, ["id-c", "id-a", "id-m", "id-b", "id-e"])
    store = _sqlite(tmp_path)
    for index in range(5):
        store.append_audit(
            session_id="s1",
            action=f"act-{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    expected = ["id-m", "id-e", "id-c", "id-b", "id-a"]
    assert [entry["id"] for entry in store.list_audit()["entries"]] == expected
    assert [entry["id"] for entry in store.list_audit("s1")["entries"]] == expected


def test_sqlite_artifact_ties_page_without_repeats_or_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch, sqlite_store_module)
    _script_ids(monkeypatch, sqlite_store_module, ["art-c", "art-a", "art-b"])
    store = _sqlite(tmp_path)
    for index in range(3):
        store.register_artifact(
            session_id="s1",
            kind="dump",
            path=tmp_path / f"f{index}.bin",
            sha256="x",
            source="test",
            size=1,
        )

    expected = ["art-c", "art-b", "art-a"]
    listed = [item["id"] for item in store.list_artifacts()["artifacts"]]
    assert listed == expected
    # Pagination must walk the same total order: no repeated or dropped rows.
    first = [item["id"] for item in store.list_artifacts(offset=0, limit=2)["artifacts"]]
    second = [item["id"] for item in store.list_artifacts(offset=2, limit=2)["artifacts"]]
    assert first + second == expected


def test_sqlite_unclean_session_ties_have_a_total_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch, sqlite_store_module)
    store = _sqlite(tmp_path)
    for session_id in ("s-c", "s-a", "s-b"):
        store.upsert_session(
            session_id=session_id,
            binary="t.exe",
            sha256="a" * 64,
            architecture="x64",
            state="created",
        )

    rows, total = store.list_unclean_sessions()
    assert total == 3
    assert [row["id"] for row in rows] == ["s-c", "s-b", "s-a"]


def test_inmemory_audit_ties_mirror_the_sqlite_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch, repo_module)
    _script_ids(monkeypatch, repo_module, ["id-c", "id-a", "id-b"])
    repo = InMemoryAnalysisRepository(tmp_path)
    for index in range(3):
        repo.append_audit(
            session_id="s1",
            action=f"act-{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    listed = [entry["id"] for entry in repo.list_audit()["entries"]]
    assert listed == ["id-c", "id-b", "id-a"]


def test_inmemory_artifact_ties_mirror_the_sqlite_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch, repo_module)
    _script_ids(monkeypatch, repo_module, ["art-c", "art-a", "art-b"])
    repo = InMemoryAnalysisRepository(tmp_path)
    for index in range(3):
        repo.register_artifact(
            session_id="s1",
            kind="dump",
            path=str(tmp_path / f"f{index}.bin"),
            sha256="x",
            source="test",
            size=1,
        )

    listed = [item["id"] for item in repo.list_artifacts()["artifacts"]]
    assert listed == ["art-c", "art-b", "art-a"]


def test_inmemory_unclean_session_ties_mirror_the_sqlite_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _freeze_clock(monkeypatch, repo_module)
    # note_session_created appends an audit row per session; those three ids
    # are consumed from the script but play no part in the assertion.
    _script_ids(monkeypatch, repo_module, ["a1", "a2", "a3"])
    repo = InMemoryAnalysisRepository(tmp_path)
    for session_id in ("s-c", "s-a", "s-b"):
        repo.note_session_created("t.exe", _created(session_id))

    rows, total = repo.list_unclean_sessions()
    assert total == 3
    assert [row["id"] for row in rows] == ["s-c", "s-b", "s-a"]


def test_gc_spares_the_just_registered_artifact_when_stamps_tie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The newest-artifact protection is positional and must track insertion.

    gc runs right after registration and never collects rows[-1], so the last
    row of its oldest-first scan must be the artifact registered last. Today
    the tie order happens to be insertion order because the sorter is fed in
    rowid order; an index on created_at -- or an id tiebreak, which is why the
    just-registered artifact here carries the *smaller* id -- would put a tied
    older artifact last instead and let gc delete the file its caller is
    about to return. Pinned to (created_at, rowid): insertion order.
    """
    _freeze_clock(monkeypatch, sqlite_store_module)
    _script_ids(monkeypatch, sqlite_store_module, ["art-z", "art-a"])
    store = _sqlite(tmp_path)
    older = tmp_path / "s1" / "old.bin"
    newest = tmp_path / "s1" / "new.bin"
    for path in (older, newest):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * 10)
    store.register_artifact(session_id="s1", kind="dump", path=older, sha256="x", source="test")
    just = store.register_artifact(
        session_id="s1", kind="dump", path=newest, sha256="x", source="test"
    )

    result = store.gc_artifacts(max_total_bytes=10)

    assert result["removed"] == ["art-z"]
    assert not older.is_file()
    assert newest.is_file()
    assert store.describe_artifact(str(just["id"])) is not None
