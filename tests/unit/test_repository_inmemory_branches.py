"""Reachable edges of the in-memory repository and the sqlite note guards.

Every track records the same lifecycle -- created, backends, artifacts,
knowledge, audit, closed -- through an AnalysisRepository. The in-memory variant
is the no-persistence fallback the service runs on when there is no database, so
its trim, artifact collection, and audit bounds have to behave the same as the
sqlite one. This file drives the branches the contract suite leaves: the
note-guards that ignore a failed or shapeless result, closing with a real
Session object, the trim that evicts knowledge/backends and their on-disk files,
and the collector's file-gone and unlinkable-file paths.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import repository as repo_module
from headless_re_mcp.core.models import (
    Result,
    RpcError,
    Session,
    SessionState,
    TargetKind,
)
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store.timeline import session_timeline_path


def _failed() -> Result:
    return Result(ok=False, error=RpcError(code="internal_error", message="nope"))


def _created(sid: str) -> Result:
    return Result(
        ok=True,
        data={
            "session": {
                "id": sid,
                "binary": "t.exe",
                "sha256": "",
                "architecture": "x86_64",
                "state": "created",
            }
        },
    )


# --------------------------------------------------------------------------- #
# note_session_created: a failed or shapeless result is ignored               #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "repo_factory",
    [InMemoryAnalysisRepository, SqliteAnalysisRepository],
)
def test_note_created_ignores_a_failed_or_shapeless_result(
    repo_factory: type, tmp_path: Path
) -> None:
    repo = repo_factory(tmp_path / repo_factory.__name__)
    repo.note_session_created("t.exe", _failed())
    repo.note_session_created("t.exe", Result(ok=True, data={"session": "not a dict"}))
    assert repo.list_unclean_sessions() == ([], 0)


# --------------------------------------------------------------------------- #
# note_session_closed                                                         #
# --------------------------------------------------------------------------- #
def test_closing_an_unknown_or_failed_session_records_nothing(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    # No such session, and nothing to update.
    repo.note_session_closed("ghost", None, Result(ok=True, data={}))
    assert repo.peek_session("ghost") is None
    # A known session whose close failed stays as it was, not marked closed.
    repo.note_session_created("t.exe", _created("known"))
    repo.note_session_closed("known", None, _failed())
    assert repo.peek_session("known")["state"] == "created"


def test_closing_with_a_session_object_captures_its_final_shape(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    session = Session(
        target=TargetKind.WEB, locator="https://x/", state=SessionState.CLOSED
    )
    repo.note_session_closed(session.id, session, Result(ok=True, data={"closed": True}))
    row = repo.peek_session(session.id)
    assert row is not None
    assert row["state"] == "closed"
    assert row["closed_cleanly"] == 1
    assert row["binary"] == "https://x/"

    # A failed close keeps the row but marks it unclean so an operator can find it.
    failed = Session(
        target=TargetKind.WEB, locator="https://y/", state=SessionState.CLOSING
    )
    repo.note_session_closed(failed.id, failed, _failed())
    assert repo.peek_session(failed.id)["closed_cleanly"] == 0


# --------------------------------------------------------------------------- #
# _trim_closed_sessions: evict facts, backends, and their on-disk files       #
# --------------------------------------------------------------------------- #
def test_trim_evicts_knowledge_backends_and_on_disk_files(tmp_path: Path) -> None:
    root = tmp_path / "root"
    repo = InMemoryAnalysisRepository(root)
    repo.retained_closed_sessions = 1
    for index in range(3):
        sid = f"c{index}"
        repo.note_session_created("t.exe", _created(sid))
        repo.record_knowledge(session_id=sid, kind="finding", key="k", value={"n": index})
        repo.record_backend(sid, "web", worker_id="w")
        # The in-memory repo never writes the timeline to disk, but a prior
        # persistent run can leave these behind; trim must reclaim them.
        timeline = session_timeline_path(root, sid)
        timeline.parent.mkdir(parents=True, exist_ok=True)
        timeline.write_text("{}\n", encoding="utf-8")
        events = root / "debug-events" / sid
        events.mkdir(parents=True, exist_ok=True)
        (events / "e.json").write_text("{}", encoding="utf-8")
        repo.note_session_closed(sid, None, Result(ok=True, data={"closed": True}))

    # Only the newest closed session survives the retention limit of one.
    assert repo.peek_session("c0") is None
    assert repo.peek_session("c2") is not None
    assert repo.list_knowledge("c0")["total"] == 0
    assert repo.list_backends("c0") == []
    # The unfiltered listing returns only the surviving session's backend.
    assert [row["session_id"] for row in repo.list_backends()] == ["c2"]
    assert not session_timeline_path(root, "c0").exists()
    assert not session_timeline_path(root, "c0").parent.exists()
    assert not (root / "debug-events" / "c0").exists()


# --------------------------------------------------------------------------- #
# gc_artifacts                                                                #
# --------------------------------------------------------------------------- #
def test_gc_breaks_immediately_when_already_within_budget(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    for name in ("a.bin", "b.bin"):
        path = tmp_path / name
        path.write_bytes(b"x" * 50)
        repo.register_artifact(
            session_id="s", kind="dump", path=path, sha256="h", source="t", size=50
        )
    result = repo.gc_artifacts(max_total_bytes=10_000)
    assert result["removed"] == []


def test_gc_drops_the_row_when_its_file_is_already_gone(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    old = tmp_path / "old.bin"
    old.write_bytes(b"x" * 50)
    new = tmp_path / "new.bin"
    new.write_bytes(b"y" * 50)
    gone = repo.register_artifact(
        session_id="s", kind="dump", path=old, sha256="1", source="t", size=50
    )
    repo.register_artifact(
        session_id="s", kind="dump", path=new, sha256="2", source="t", size=50
    )
    old.unlink()
    result = repo.gc_artifacts(max_total_bytes=1)
    assert gone["id"] in result["removed"]
    assert repo.describe_artifact(str(gone["id"])) is None


def test_gc_skips_a_file_it_cannot_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    old = tmp_path / "old.bin"
    old.write_bytes(b"x" * 50)
    new = tmp_path / "new.bin"
    new.write_bytes(b"y" * 50)
    stuck = repo.register_artifact(
        session_id="s", kind="dump", path=old, sha256="1", source="t", size=50
    )
    repo.register_artifact(
        session_id="s", kind="dump", path=new, sha256="2", source="t", size=50
    )

    def boom_unlink(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError("held open")

    monkeypatch.setattr(Path, "unlink", boom_unlink)
    result = repo.gc_artifacts(max_total_bytes=1)
    assert result["skipped_count"] == 1
    assert str(stuck["id"]) not in result["removed"]
    assert repo.describe_artifact(str(stuck["id"])) is not None


# --------------------------------------------------------------------------- #
# peek_session and the audit trim / all-session listing                       #
# --------------------------------------------------------------------------- #
def test_peek_session_returns_a_copy_or_none(tmp_path: Path) -> None:
    repo = InMemoryAnalysisRepository(tmp_path)
    assert repo.peek_session("ghost") is None
    repo.note_session_created("t.exe", _created("s1"))
    row = repo.peek_session("s1")
    assert row is not None
    assert row["id"] == "s1"


def test_audit_trims_to_the_newest_rows_and_lists_across_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repo_module, "AUDIT_RETAINED_ROWS", 2)
    repo = InMemoryAnalysisRepository(tmp_path)
    for index in range(3):
        repo.append_audit(
            session_id="s",
            action=f"a{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )
    listed = repo.list_audit()  # no session filter
    assert listed["total"] == 2
    actions = [entry["action"] for entry in listed["entries"]]
    assert actions == ["a2", "a1"]
