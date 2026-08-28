"""Close bookkeeping, retention trims, and gc failure arms of the repository port.

``InMemoryAnalysisRepository`` documents itself as having the same observable
contract as the SQLite implementation, so the shared behaviors here run against
both: a divergence would let a custom composition pass its tests against the
fake and then corrupt rows against the real store.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.repository as repository_module
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
from headless_re_mcp.core.store.timeline import session_timeline_path

JsonObject = dict[str, Any]

AnyRepository = SqliteAnalysisRepository | InMemoryAnalysisRepository

BOTH_IMPLEMENTATIONS = pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)


def _ok(data: JsonObject) -> Result[JsonObject]:
    return Result(ok=True, data=data)


def _failed() -> Result[JsonObject]:
    return Result(ok=False, error=RpcError(code="internal_error", message="close failed"))


def _created_payload(session_id: str) -> Result[JsonObject]:
    return _ok(
        {
            "session": {
                "id": session_id,
                "binary": "sample.exe",
                "sha256": "c" * 64,
                "architecture": "x64",
                "state": "created",
            }
        }
    )


def _live_session(session_id: str) -> Session:
    return Session(
        id=session_id,
        binary=Path("sample.exe"),
        sha256="c" * 64,
        architecture=Architecture.X64,
        state=SessionState.CLOSED,
    )


def _register(repository: AnyRepository, path: Path, **overrides: Any) -> JsonObject:
    fields: JsonObject = {
        "session_id": "sid",
        "kind": "dump",
        "path": path,
        "sha256": "0" * 64,
        "source": "test",
    }
    fields.update(overrides)
    return repository.register_artifact(**fields)


@BOTH_IMPLEMENTATIONS
def test_a_failed_create_result_writes_no_session_row(
    tmp_path: Path, repository_type: type[AnyRepository]
) -> None:
    repository = repository_type(tmp_path)

    repository.note_session_created("sample.exe", _failed())

    _, total = repository.list_unclean_sessions()
    assert total == 0


@BOTH_IMPLEMENTATIONS
def test_a_create_result_with_a_non_object_session_writes_no_row(
    tmp_path: Path, repository_type: type[AnyRepository]
) -> None:
    repository = repository_type(tmp_path)

    repository.note_session_created("sample.exe", _ok({"session": "bogus"}))

    _, total = repository.list_unclean_sessions()
    assert total == 0


@BOTH_IMPLEMENTATIONS
def test_closing_an_unknown_evicted_session_creates_no_ghost_row(
    tmp_path: Path, repository_type: type[AnyRepository]
) -> None:
    """An ok close of an id the store never saw must not invent a session."""
    repository = repository_type(tmp_path)

    repository.note_session_closed("never-seen", None, _ok({"ok": True}))

    assert repository.peek_session("never-seen") is None
    assert repository.list_timeline("never-seen")["total"] == 0


@BOTH_IMPLEMENTATIONS
def test_a_failed_close_of_an_evicted_session_leaves_the_row_alone(
    tmp_path: Path, repository_type: type[AnyRepository]
) -> None:
    repository = repository_type(tmp_path)
    repository.note_session_created("sample.exe", _created_payload("sid"))

    repository.note_session_closed("sid", None, _failed())

    row = repository.peek_session("sid")
    assert row is not None
    assert row["state"] == "created"
    assert not row["closed_cleanly"]
    events = repository.list_timeline("sid")["events"]
    assert all(item["event"] != "session.closed" for item in events)


@BOTH_IMPLEMENTATIONS
def test_a_clean_live_close_records_the_final_session_state(
    tmp_path: Path, repository_type: type[AnyRepository]
) -> None:
    repository = repository_type(tmp_path)
    repository.note_session_created("sample.exe", _created_payload("sid"))

    repository.note_session_closed("sid", _live_session("sid"), _ok({"ok": True}))

    row = repository.peek_session("sid")
    assert row is not None
    assert row["state"] == "closed"
    assert row["closed_cleanly"]
    assert row["sha256"] == "c" * 64
    assert row["architecture"] == "x64"
    closed = [
        item
        for item in repository.list_timeline("sid")["events"]
        if item["event"] == "session.closed"
    ]
    assert [item["message"] for item in closed] == ["session closed"]
    actions = [item["action"] for item in repository.list_audit("sid")["entries"]]
    assert "session.close" in actions


@BOTH_IMPLEMENTATIONS
def test_a_failed_live_close_stays_on_the_unclean_worklist(
    tmp_path: Path, repository_type: type[AnyRepository]
) -> None:
    repository = repository_type(tmp_path)
    repository.note_session_created("sample.exe", _created_payload("sid"))

    repository.note_session_closed("sid", _live_session("sid"), _failed())

    row = repository.peek_session("sid")
    assert row is not None
    assert not row["closed_cleanly"]
    unclean, total = repository.list_unclean_sessions()
    assert total == 1
    assert unclean[0]["id"] == "sid"
    closed = [
        item
        for item in repository.list_timeline("sid")["events"]
        if item["event"] == "session.closed"
    ]
    assert [item["message"] for item in closed] == ["session close failed"]


def test_the_sqlite_store_reports_writable_when_healthy(tmp_path: Path) -> None:
    SqliteAnalysisRepository(tmp_path).check_writable()


def test_retention_trim_removes_the_evicted_sessions_side_state(tmp_path: Path) -> None:
    """Evicting a closed session must reap its knowledge, backends, and disk residue."""
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.retained_closed_sessions = 1
    for session_id in ("aaaa", "bbbb"):
        repository.note_session_created("sample.exe", _created_payload(session_id))
        repository.record_knowledge(session_id=session_id, kind="note", key="k", value={"v": 1})
        repository.record_backend(session_id, "ida", worker_id="w", pid=1, endpoint="e")
    timeline_file = session_timeline_path(repository.artifact_root, "aaaa")
    timeline_file.parent.mkdir(parents=True, exist_ok=True)
    timeline_file.write_text("{}\n", encoding="utf-8")
    events_dir = repository.artifact_root / "debug-events" / "aaaa"
    events_dir.mkdir(parents=True)
    (events_dir / "events.jsonl").write_text("{}\n", encoding="utf-8")

    repository.note_session_closed("aaaa", _live_session("aaaa"), _ok({"ok": True}))
    repository.note_session_closed("bbbb", _live_session("bbbb"), _ok({"ok": True}))

    assert repository.peek_session("aaaa") is None
    assert repository.peek_session("bbbb") is not None
    assert repository.list_knowledge("aaaa")["total"] == 0
    assert repository.list_knowledge("bbbb")["total"] == 1
    assert repository.list_backends("aaaa") == []
    assert not timeline_file.exists()
    assert not timeline_file.parent.exists()
    assert not events_dir.exists()


def test_backend_listing_without_a_filter_reports_every_session(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.record_backend("aaaa", "ida", worker_id="w1")
    repository.record_backend("bbbb", "x64dbg", worker_id="w2")

    everything = repository.list_backends()
    assert [item["session_id"] for item in everything] == ["aaaa", "bbbb"]
    only_a = repository.list_backends("aaaa")
    assert [item["kind"] for item in only_a] == ["ida"]


def test_gc_stops_once_the_total_is_back_under_budget(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    paths = [tmp_path / name for name in ("one.bin", "two.bin", "three.bin")]
    recorded = []
    for path in paths:
        path.write_bytes(b"x" * 10)
        recorded.append(_register(repository, path))

    report = repository.gc_artifacts(max_total_bytes=20)

    assert report["removed"] == [recorded[0]["id"]]
    assert report["bytes_remaining_estimate"] == 20
    assert not paths[0].exists()
    assert paths[1].is_file()
    assert paths[2].is_file()


def test_gc_reports_an_artifact_it_cannot_delete_and_keeps_the_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file the OS refuses to unlink must stay accounted for, not vanish."""
    repository = InMemoryAnalysisRepository(tmp_path)
    locked = tmp_path / "locked.bin"
    locked.write_bytes(b"x" * 10)
    newest = tmp_path / "newest.bin"
    newest.write_bytes(b"x" * 10)
    kept = _register(repository, locked)
    _register(repository, newest)
    original_unlink = Path.unlink

    def deny(self: Path, missing_ok: bool = False) -> None:
        if self == locked:
            raise PermissionError("file is in use")
        original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", deny)
    report = repository.gc_artifacts(max_total_bytes=1)

    assert report["removed"] == []
    assert [item["id"] for item in report["skipped"]] == [kept["id"]]
    assert "PermissionError" in report["skipped"][0]["reason"]
    assert repository.describe_artifact(str(kept["id"])) is not None
    assert locked.is_file()


def test_gc_drops_the_row_for_an_artifact_whose_file_is_already_gone(
    tmp_path: Path,
) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    ghost = _register(repository, tmp_path / "already-deleted.bin", size=10)
    newest = tmp_path / "newest.bin"
    newest.write_bytes(b"x" * 10)
    _register(repository, newest)

    report = repository.gc_artifacts(max_total_bytes=1)

    assert report["removed"] == [ghost["id"]]
    assert report["invalid_paths"] == []
    assert repository.describe_artifact(str(ghost["id"])) is None


def test_audit_retention_keeps_only_the_newest_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repository_module, "AUDIT_RETAINED_ROWS", 2)
    repository = InMemoryAnalysisRepository(tmp_path)
    for index in range(3):
        repository.append_audit(
            session_id="sid",
            action=f"action.{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    listing = repository.list_audit()

    assert listing["total"] == 2
    actions = {item["action"] for item in listing["entries"]}
    assert actions == {"action.1", "action.2"}


def test_peek_session_hands_back_a_copy_not_the_stored_row(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.note_session_created("sample.exe", _created_payload("sid"))

    row = repository.peek_session("sid")
    assert row is not None
    row["state"] = "tampered"

    fresh = repository.peek_session("sid")
    assert fresh is not None
    assert fresh["state"] == "created"
