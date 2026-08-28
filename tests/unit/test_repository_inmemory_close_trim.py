"""Close, trim, gc and listing edges of the in-memory analysis repository.

test_architecture_state_repository.py drives the shared contract for both
backends, but it only ever closes a session with ``session=None`` and never
records knowledge or backends on a session that later gets trimmed. That
leaves the in-memory repository's live-session close branch, the per-session
knowledge/backend eviction, the on-disk timeline and debug-events cleanup,
several gc arms, and the unfiltered list branches unverified. This file drives
each of those directly against InMemoryAnalysisRepository.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core import repository as repo_module
from headless_re_mcp.core.models import (
    Architecture,
    Result,
    RpcError,
    Session,
    SessionState,
)
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)

JsonObject = dict[str, object]


def _repo(tmp_path: Path) -> InMemoryAnalysisRepository:
    return InMemoryAnalysisRepository(tmp_path)


def _failed() -> Result[JsonObject]:
    return Result[JsonObject](ok=False, error=RpcError(code="backend_error", message="nope"))


def _created(sid: str, *, binary: str = "t.exe", arch: str = "x64") -> Result[JsonObject]:
    return Result[JsonObject](
        ok=True,
        data={
            "session": {
                "id": sid,
                "binary": binary,
                "sha256": "a" * 64,
                "architecture": arch,
                "state": "created",
            }
        },
    )


def _session(sid: str) -> Session:
    return Session(
        id=sid,
        binary=Path("t.exe"),
        locator="t.exe",
        sha256="a" * 64,
        architecture=Architecture.X64,
        state=SessionState.CLOSED,
    )


# --------------------------------------------------------------------------- #
# note_session_created guards                                                 #
# --------------------------------------------------------------------------- #
def test_created_ignores_a_failed_result(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", _failed())
    assert repo.list_unclean_sessions() == ([], 0)


def test_created_ignores_a_result_whose_session_is_not_a_mapping(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", Result[JsonObject](ok=True, data={"session": "not-a-dict"}))
    assert repo.list_unclean_sessions() == ([], 0)


# --------------------------------------------------------------------------- #
# note_session_closed: session is None                                        #
# --------------------------------------------------------------------------- #
def test_closing_an_unknown_id_with_no_object_creates_nothing(tmp_path: Path) -> None:
    """Closing something the registry never held must not conjure a row."""
    repo = _repo(tmp_path)
    repo.note_session_closed("ghost", None, Result[JsonObject](ok=True, data={"closed": True}))
    assert repo.peek_session("ghost") is None
    assert repo.list_unclean_sessions() == ([], 0)


def test_closing_a_known_id_with_a_failed_result_leaves_it_unclean(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", _created("s1"))
    repo.note_session_closed("s1", None, _failed())
    unclean, total = repo.list_unclean_sessions()
    assert total == 1
    assert [row["id"] for row in unclean] == ["s1"]


# --------------------------------------------------------------------------- #
# note_session_closed: a live Session object                                  #
# --------------------------------------------------------------------------- #
def test_closing_a_live_session_object_marks_it_cleanly_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", _created("s1"))

    repo.note_session_closed("s1", _session("s1"), Result[JsonObject](ok=True, data={"ok": True}))

    row = repo.peek_session("s1")
    assert row is not None
    assert row["state"] == "closed"
    assert row["closed_cleanly"] == 1
    assert repo.list_unclean_sessions() == ([], 0)
    events = [item["event"] for item in repo.list_timeline("s1")["events"]]
    assert "session.closed" in events
    messages = [item["message"] for item in repo.list_timeline("s1")["events"]]
    assert "session closed" in messages


def test_closing_a_live_session_object_that_failed_stays_unclean(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", _created("s1"))

    repo.note_session_closed("s1", _session("s1"), _failed())

    row = repo.peek_session("s1")
    assert row is not None
    assert row["closed_cleanly"] == 0
    assert [r["id"] for r in repo.list_unclean_sessions()[0]] == ["s1"]
    messages = [item["message"] for item in repo.list_timeline("s1")["events"]]
    assert "session close failed" in messages


def test_closing_preserves_the_original_created_at(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", _created("s1"))
    created_at = repo.peek_session("s1")["created_at"]  # type: ignore[index]

    repo.note_session_closed("s1", _session("s1"), Result[JsonObject](ok=True, data={"ok": True}))

    assert repo.peek_session("s1")["created_at"] == created_at  # type: ignore[index]


# --------------------------------------------------------------------------- #
# _trim_closed_sessions: knowledge, backends, on-disk cleanup                 #
# --------------------------------------------------------------------------- #
def test_trim_forgets_knowledge_and_backends_of_dropped_sessions(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.retained_closed_sessions = 1
    for index in range(3):
        sid = f"closed-{index}"
        repo.note_session_created("t.exe", _created(sid))
        repo.record_knowledge(session_id=sid, kind="function", key="fact", value={"n": index})
        repo.record_backend(sid, "ida", worker_id=f"ida:{index}", pid=index, endpoint="stdio://x")
        repo.note_session_closed(sid, None, Result[JsonObject](ok=True, data={"closed": True}))

    # Only the newest cleanly-closed session survives the trim.
    assert repo.peek_session("closed-2") is not None
    assert repo.peek_session("closed-0") is None
    assert repo.list_knowledge("closed-0")["total"] == 0
    assert repo.list_backends("closed-0") == []
    assert repo.list_knowledge("closed-2")["total"] == 1
    assert len(repo.list_backends("closed-2")) == 1


def test_trim_deletes_the_on_disk_timeline_and_debug_events(tmp_path: Path) -> None:
    """The dropped session's file-backed timeline and event log go with it."""
    repo = _repo(tmp_path)
    repo.retained_closed_sessions = 1

    doomed_timeline = tmp_path / "sessions" / "closed-0" / "timeline.jsonl"
    doomed_timeline.parent.mkdir(parents=True)
    doomed_timeline.write_text("{}\n", encoding="utf-8")
    doomed_events = tmp_path / "debug-events" / "closed-0"
    doomed_events.mkdir(parents=True)
    (doomed_events / "events.jsonl").write_text("{}\n", encoding="utf-8")

    for index in range(2):
        sid = f"closed-{index}"
        repo.note_session_created("t.exe", _created(sid))
        repo.note_session_closed(sid, None, Result[JsonObject](ok=True, data={"closed": True}))

    assert repo.peek_session("closed-0") is None
    assert not doomed_timeline.exists()
    assert not doomed_timeline.parent.exists()
    assert not doomed_events.exists()


# --------------------------------------------------------------------------- #
# gc_artifacts arms                                                           #
# --------------------------------------------------------------------------- #
def _register(
    repo: InMemoryAnalysisRepository, path: Path, *, sha: str, size: int, create: bool = True
) -> JsonObject:
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
    return repo.register_artifact(
        session_id="s", kind="dump", path=path, sha256=sha, source="test", size=size
    )


def test_gc_stops_once_it_is_back_under_budget(tmp_path: Path) -> None:
    """Eviction breaks the moment the running total fits, leaving the rest."""
    repo = _repo(tmp_path)
    for index in range(4):
        _register(repo, tmp_path / "art" / f"e{index}.bin", sha=str(index) * 64, size=10)

    result = repo.gc_artifacts(max_total_bytes=25)

    # 40 bytes over a 25 budget: drop the two oldest to reach 20, then stop
    # rather than walking to the newest-protected tail.
    assert result["count"] == 2
    assert result["bytes_remaining_estimate"] == 20


def test_gc_drops_a_collectable_row_whose_file_already_vanished(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    gone = _register(
        repo, tmp_path / "trace" / "s" / "gone.bin", sha="1" * 64, size=64, create=False
    )
    _register(repo, tmp_path / "trace" / "s" / "newest.bin", sha="2" * 64, size=64)

    result = repo.gc_artifacts(max_total_bytes=1)

    assert str(gone["id"]) in result["removed"]
    assert repo.describe_artifact(str(gone["id"])) is None


def test_gc_skips_a_row_whose_file_cannot_be_unlinked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    stuck = _register(repo, tmp_path / "trace" / "s" / "stuck.bin", sha="1" * 64, size=64)
    _register(repo, tmp_path / "trace" / "s" / "newest.bin", sha="2" * 64, size=64)

    def refuse_unlink(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError("held open by another handle")

    monkeypatch.setattr(Path, "unlink", refuse_unlink)

    result = repo.gc_artifacts(max_total_bytes=1)

    assert result["skipped_count"] == 1
    assert result["skipped"][0]["id"] == str(stuck["id"])
    assert repo.describe_artifact(str(stuck["id"])) is not None
    assert (tmp_path / "trace" / "s" / "stuck.bin").is_file()


# --------------------------------------------------------------------------- #
# peek_session, audit trim, unfiltered listings                              #
# --------------------------------------------------------------------------- #
def test_peek_session_returns_an_isolated_copy_or_none(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.note_session_created("t.exe", _created("s1"))

    row = repo.peek_session("s1")
    assert row is not None and row["id"] == "s1"
    row["binary"] = "mutated"
    assert repo.peek_session("s1")["binary"] == "t.exe"  # type: ignore[index]
    assert repo.peek_session("missing") is None


def test_audit_log_trims_to_the_newest_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repo_module, "AUDIT_RETAINED_ROWS", 3)
    # A coarse Windows clock can stamp every row identically, which would leave
    # the newest-first sort to fall back to insertion order; tick it explicitly.
    ticks = iter(range(100))
    base = datetime(2024, 1, 1, tzinfo=UTC)
    fake_clock = SimpleNamespace(now=lambda tz=UTC: base + timedelta(seconds=next(ticks)))
    monkeypatch.setattr(repo_module, "datetime", fake_clock)
    repo = _repo(tmp_path)
    for index in range(6):
        repo.append_audit(
            session_id="s1",
            action=f"action-{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    actions = [entry["action"] for entry in repo.list_audit("s1", limit=50)["entries"]]
    assert actions == ["action-5", "action-4", "action-3"]


def test_list_audit_without_a_session_filter_returns_every_row(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.append_audit(session_id="s1", action="a", params_summary={}, ok=True, result_summary={})
    repo.append_audit(session_id="s2", action="b", params_summary={}, ok=True, result_summary={})

    listed = repo.list_audit()
    assert listed["total"] == 2
    assert {entry["session_id"] for entry in listed["entries"]} == {"s1", "s2"}


def test_list_backends_without_a_session_filter_returns_all_sorted(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.record_backend("s2", "ida", worker_id="w2", pid=2, endpoint="e2")
    repo.record_backend("s1", "x64dbg", worker_id="w1", pid=1, endpoint="e1")

    listed = repo.list_backends()
    assert [(item["session_id"], item["kind"]) for item in listed] == [
        ("s1", "x64dbg"),
        ("s2", "ida"),
    ]


# --------------------------------------------------------------------------- #
# per-session timeline and knowledge trimming, artifact guards               #
# --------------------------------------------------------------------------- #
def test_timeline_keeps_only_the_newest_entries_per_session(tmp_path: Path) -> None:
    """The in-memory timeline is the one list that must self-cap like the file."""
    repo = _repo(tmp_path)
    repo.retained_timeline_per_session = 2
    for index in range(5):
        repo.append_timeline("s1", f"e{index}", "msg", n=index)

    listed = repo.list_timeline("s1")
    assert listed["total"] == 2
    assert [item["event"] for item in listed["events"]] == ["e3", "e4"]


def test_knowledge_is_trimmed_to_the_newest_facts_per_session(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    repo.retained_knowledge_per_session = 2
    for index in range(5):
        repo.record_knowledge(
            session_id="s1", kind="function", key=f"key-{index}", value={"n": index}
        )

    listed = repo.list_knowledge("s1")
    assert listed["total"] == 2
    assert {entry["key"] for entry in listed["entries"]} == {"key-3", "key-4"}


def test_register_artifact_refuses_a_negative_size(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(ValueError, match="cannot be negative"):
        repo.register_artifact(
            session_id="s",
            kind="dump",
            path=tmp_path / "missing.bin",
            sha256="1" * 64,
            source="test",
            size=-1,
        )


def test_list_artifacts_without_a_session_filter_returns_all(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _register(repo, tmp_path / "art" / "a.bin", sha="1" * 64, size=8)
    _register(repo, tmp_path / "art" / "b.bin", sha="2" * 64, size=8)

    listed = repo.list_artifacts()
    assert listed["total"] == 2


# --------------------------------------------------------------------------- #
# the SQLite-backed twin shares the note_session_created guards              #
# --------------------------------------------------------------------------- #
def test_sqlite_created_ignores_a_failed_result(tmp_path: Path) -> None:
    repo = SqliteAnalysisRepository(tmp_path / "db")
    repo.note_session_created("t.exe", _failed())
    assert repo.list_unclean_sessions() == ([], 0)


def test_sqlite_created_ignores_a_non_mapping_session(tmp_path: Path) -> None:
    repo = SqliteAnalysisRepository(tmp_path / "db")
    repo.note_session_created("t.exe", Result[JsonObject](ok=True, data={"session": "not-a-dict"}))
    assert repo.list_unclean_sessions() == ([], 0)
