"""Edge-path coverage for core/repository.py.

Targets the guard returns of both repository implementations, the in-memory
close/trim bookkeeping, and the artifact garbage-collection arms that only
fire on unusual on-disk states.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, Session, SessionState
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.store.sqlite_store import AUDIT_RETAINED_ROWS
from headless_re_mcp.core.store.timeline import session_timeline_path


def _closed_session(session_id: str) -> Session:
    return Session(
        id=session_id,
        binary=Path("C:/samples/app.exe"),
        locator="C:/samples/app.exe",
        sha256="ab" * 32,
        architecture=Architecture.X64,
        state=SessionState.CLOSED,
    )


# --- guard returns shared by both implementations ---


def test_sqlite_note_created_ignores_a_failed_result(tmp_path: Path) -> None:
    repo = SqliteAnalysisRepository(tmp_path)
    repo.note_session_created("app.exe", _failure(RuntimeError("boom")))
    assert repo.list_backends() == []


def test_sqlite_note_created_ignores_a_result_without_a_session(tmp_path: Path) -> None:
    repo = SqliteAnalysisRepository(tmp_path)
    repo.note_session_created("app.exe", _success({"session": "not-a-dict"}))
    unclean, total = repo.list_unclean_sessions()
    assert unclean == []
    assert total == 0


def test_memory_note_created_ignores_a_failed_result(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.note_session_created("app.exe", _failure(RuntimeError("boom")))
    assert repo.peek_session("anything") is None


def test_memory_note_created_ignores_a_result_without_a_session(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.note_session_created("app.exe", _success({"session": None}))
    unclean, total = repo.list_unclean_sessions()
    assert unclean == []
    assert total == 0


def test_memory_close_of_an_unknown_session_creates_nothing(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.note_session_closed("ghost", None, _success({"ok": True}))
    assert repo.peek_session("ghost") is None
    assert repo.list_timeline("ghost")["total"] == 0


# --- close with a live Session object ---


def test_memory_close_records_a_clean_close_from_the_session(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    session = _closed_session("live-1")

    repo.note_session_closed("live-1", session, _success({"ok": True}))

    row = repo.peek_session("live-1")
    assert row is not None
    assert row["state"] == "closed"
    assert row["closed_cleanly"] == 1
    assert row["architecture"] == "x64"
    events = repo.list_timeline("live-1")["events"]
    assert any(item["message"] == "session closed" for item in events)
    audit = repo.list_audit("live-1")["entries"]
    assert any(item["action"] == "session.close" and item["ok"] == 1 for item in audit)


def test_memory_close_records_a_failed_close_without_trimming(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    session = _closed_session("live-2")

    repo.note_session_closed("live-2", session, _failure(RuntimeError("close failed")))

    row = repo.peek_session("live-2")
    assert row is not None
    assert row["closed_cleanly"] == 0
    events = repo.list_timeline("live-2")["events"]
    assert any(item["message"] == "session close failed" for item in events)


# --- closed-session trimming sweeps every per-session store ---


def test_trim_sweeps_knowledge_backends_and_on_disk_leftovers(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.retained_closed_sessions = 1
    repo._sessions["old"] = {
        "id": "old",
        "closed_cleanly": 1,
        "updated_at": "2020-01-01T00:00:00+00:00",
    }
    repo._sessions["new"] = {
        "id": "new",
        "closed_cleanly": 1,
        "updated_at": "2021-01-01T00:00:00+00:00",
    }
    repo._knowledge[("old", "note", "k")] = {
        "session_id": "old",
        "kind": "note",
        "key": "k",
        "value": {},
        "created_at": "2020-01-01T00:00:00+00:00",
        "updated_at": "2020-01-01T00:00:00+00:00",
    }
    repo._backends[("old", "dynamic")] = {"session_id": "old", "kind": "dynamic"}
    repo._timeline["old"] = [{"event": "session.created"}]
    timeline_file = session_timeline_path(tmp_path, "old")
    timeline_file.parent.mkdir(parents=True, exist_ok=True)
    timeline_file.write_text("{}\n", encoding="utf-8")
    events_dir = tmp_path / "debug-events" / "old"
    events_dir.mkdir(parents=True)
    (events_dir / "event.json").write_text("{}", encoding="utf-8")

    repo._trim_closed_sessions()

    assert "old" not in repo._sessions
    assert "new" in repo._sessions
    assert ("old", "note", "k") not in repo._knowledge
    assert ("old", "dynamic") not in repo._backends
    assert "old" not in repo._timeline
    assert not timeline_file.exists()
    assert not timeline_file.parent.exists()
    assert not events_dir.exists()


def test_trim_skips_an_id_the_path_guard_refuses(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.retained_closed_sessions = 0
    repo._sessions[".."] = {
        "id": "..",
        "closed_cleanly": 1,
        "updated_at": "2020-01-01T00:00:00+00:00",
    }

    repo._trim_closed_sessions()

    assert ".." not in repo._sessions
    assert tmp_path.is_dir()


def test_append_timeline_keeps_only_the_newest_entries(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.retained_timeline_per_session = 2
    for index in range(3):
        repo.append_timeline("s1", f"event.{index}", f"message {index}")

    events = repo.list_timeline("s1")["events"]

    assert [item["event"] for item in events] == ["event.1", "event.2"]


# --- backend listing without a filter ---


def test_list_backends_without_a_filter_returns_every_row(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo.record_backend("s1", "dynamic", worker_id="w1", pid=42, endpoint="tcp://x")
    repo.record_backend("s2", "static", pid="not-an-int")

    rows = repo.list_backends()

    assert [(row["session_id"], row["kind"]) for row in rows] == [
        ("s1", "dynamic"),
        ("s2", "static"),
    ]
    assert rows[0]["pid"] == 42
    assert rows[1]["pid"] is None


# --- gc_artifacts arms ---


def _register(repo: InMemoryAnalysisRepository, path: Path, *, size: int, at: str) -> str:
    item = repo.register_artifact(
        session_id="s",
        kind="dump",
        path=str(path),
        size=size,
        sha256="00" * 32,
        source="test",
    )
    artifact_id = str(item["id"])
    repo._artifacts[artifact_id]["created_at"] = at
    return artifact_id


def test_gc_stops_once_the_total_fits_the_budget(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    _register(repo, tmp_path / "gone-a.bin", size=10, at="2020-01-01T00:00:00+00:00")
    _register(repo, tmp_path / "gone-b.bin", size=10, at="2020-01-02T00:00:00+00:00")

    report = repo.gc_artifacts(max_total_bytes=1_000_000)

    assert report["removed"] == []
    assert report["bytes_remaining_estimate"] == 20


def test_gc_drops_the_record_of_an_artifact_with_no_file(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    oldest = _register(
        repo, tmp_path / "vanished.bin", size=100, at="2020-01-01T00:00:00+00:00"
    )
    newest_path = tmp_path / "kept.bin"
    newest_path.write_bytes(b"x" * 100)
    _register(repo, newest_path, size=100, at="2020-01-02T00:00:00+00:00")

    report = repo.gc_artifacts(max_total_bytes=1)

    assert report["removed"] == [oldest]
    assert repo.describe_artifact(oldest) is None


def test_gc_skips_a_file_it_cannot_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    stuck_path = tmp_path / "stuck.bin"
    stuck_path.write_bytes(b"x" * 100)
    stuck = _register(repo, stuck_path, size=100, at="2020-01-01T00:00:00+00:00")
    newest_path = tmp_path / "kept.bin"
    newest_path.write_bytes(b"x" * 100)
    _register(repo, newest_path, size=100, at="2020-01-02T00:00:00+00:00")

    def _refuse(self: Path, missing_ok: bool = False) -> None:
        raise OSError("file is locked")

    monkeypatch.setattr(Path, "unlink", _refuse)

    report = repo.gc_artifacts(max_total_bytes=1)

    assert report["removed"] == []
    assert [item["id"] for item in report["skipped"]] == [stuck]
    assert "OSError" in report["skipped"][0]["reason"]
    assert repo.describe_artifact(stuck) is not None


# --- audit retention cap ---


def test_append_audit_trims_to_the_retained_row_cap(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    repo._audit = [{"id": str(index)} for index in range(AUDIT_RETAINED_ROWS)]

    repo.append_audit(
        session_id=None,
        action="final",
        params_summary={},
        ok=True,
        result_summary={},
    )

    assert len(repo._audit) == AUDIT_RETAINED_ROWS
    assert repo._audit[-1]["action"] == "final"
    assert repo._audit[0]["id"] == "1"
