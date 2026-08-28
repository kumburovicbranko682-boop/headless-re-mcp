"""Session lifecycle, retention trim, and gc branches of InMemoryAnalysisRepository.

The in-memory repository is a production port implementation, not a test mock:
custom compositions may run on it exclusively. Its session close/trim/gc code
paths must therefore honor the same observable contract as the SQLite variant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import repository as repository_module
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

JsonObject = dict[str, object]


def _failed() -> Result[JsonObject]:
    return Result(ok=False, error=RpcError(code="boom", message="boom"))


def _ok(data: JsonObject | None = None) -> Result[JsonObject]:
    return Result(ok=True, data=data if data is not None else {})


def _created(session_id: str) -> Result[JsonObject]:
    return _ok({"session": {"id": session_id, "sha256": "s", "state": "created"}})


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_note_session_created_ignores_failures_and_non_dict_sessions(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    repository = repository_type(tmp_path)

    repository.note_session_created("a.exe", _failed())
    repository.note_session_created("a.exe", Result(ok=True, data=None))
    repository.note_session_created("a.exe", _ok({"session": "not a mapping"}))

    unclean, total = repository.list_unclean_sessions()
    assert unclean == []
    assert total == 0


def test_close_without_session_object_needs_existing_row_and_ok_result(
    tmp_path: Path,
) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)

    repository.note_session_closed("ghost", None, _ok({"closed": True}))
    assert repository.peek_session("ghost") is None

    repository.note_session_created("a.exe", _created("real"))
    repository.note_session_closed("real", None, _failed())
    row = repository.peek_session("real")
    assert row is not None
    assert row["state"] == "created"
    assert row["closed_cleanly"] == 0


def test_close_with_live_session_records_state_and_clean_flag(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.note_session_created("a.exe", _created("sid-live"))
    session = Session(
        id="sid-live",
        binary=tmp_path / "a.exe",
        sha256="deadbeef",
        architecture=Architecture.X64,
        state=SessionState.CLOSED,
    )

    repository.note_session_closed("sid-live", session, _ok({"closed": True}))

    row = repository.peek_session("sid-live")
    assert row is not None
    assert row["state"] == "closed"
    assert row["sha256"] == "deadbeef"
    assert row["architecture"] == "x64"
    assert row["closed_cleanly"] == 1
    events = repository.list_timeline("sid-live")["events"]
    assert isinstance(events, list)
    assert events[-1]["message"] == "session closed"


def test_close_failure_with_live_session_keeps_row_unclean(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    session = Session(id="sid-fail", locator="frida://device/pkg", state=SessionState.FAILED)

    repository.note_session_closed("sid-fail", session, _failed())

    row = repository.peek_session("sid-fail")
    assert row is not None
    assert row["binary"] == "frida://device/pkg"
    assert row["architecture"] == ""
    assert row["closed_cleanly"] == 0
    events = repository.list_timeline("sid-fail")["events"]
    assert isinstance(events, list)
    assert events[-1]["message"] == "session close failed"
    unclean, _ = repository.list_unclean_sessions()
    assert [item["id"] for item in unclean] == ["sid-fail"]


def test_trim_drops_oldest_closed_session_and_its_disk_state(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.retained_closed_sessions = 1
    # On an updated_at tie the trim sorts by id descending, so name the
    # session that must survive "zzz" to keep the assertion deterministic.
    old_sid, new_sid = "aaa-old", "zzz-new"
    for sid in (old_sid, new_sid):
        repository.note_session_created("a.exe", _created(sid))
        repository.record_knowledge(session_id=sid, kind="note", key="k", value={"v": 1})
        repository.record_backend(sid, "ida", worker_id="w1", pid=7)
    timeline_file = session_timeline_path(tmp_path, old_sid)
    timeline_file.parent.mkdir(parents=True, exist_ok=True)
    timeline_file.write_text("{}\n", encoding="utf-8")
    events_dir = tmp_path / "debug-events" / old_sid
    events_dir.mkdir(parents=True)
    (events_dir / "events.db").write_bytes(b"x")

    repository.note_session_closed(old_sid, None, _ok({"closed": True}))
    repository.note_session_closed(new_sid, None, _ok({"closed": True}))

    assert repository.peek_session(old_sid) is None
    assert repository.peek_session(new_sid) is not None
    assert repository.list_knowledge(old_sid)["entries"] == []
    assert repository.list_backends(old_sid) == []
    assert repository.list_backends(new_sid) != []
    assert not timeline_file.exists()
    assert not timeline_file.parent.exists()
    assert not events_dir.exists()


def test_trim_skips_session_ids_the_timeline_path_guard_refuses(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.retained_closed_sessions = 0
    hostile = "../escape"
    repository._sessions[hostile] = {
        "id": hostile,
        "binary": "a.exe",
        "sha256": "",
        "architecture": "",
        "state": "created",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "closed_cleanly": 1,
    }

    repository._trim_closed_sessions()

    assert repository.peek_session(hostile) is None
    assert tmp_path.exists()


def test_list_backends_returns_all_when_unfiltered(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.record_backend("s1", "ida", worker_id="w1")
    repository.record_backend("s2", "x64dbg", worker_id="w2", pid="not-an-int")

    everything = repository.list_backends()
    assert [(item["session_id"], item["kind"]) for item in everything] == [
        ("s1", "ida"),
        ("s2", "x64dbg"),
    ]
    assert everything[1]["pid"] is None
    assert [item["kind"] for item in repository.list_backends("s2")] == ["x64dbg"]


def test_gc_removes_records_of_vanished_files_and_skips_undeletable_ones(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    vanished = repository.register_artifact(
        session_id="s",
        kind="dump",
        path=str(tmp_path / "vanished.bin"),
        size=100,
        sha256="a",
        source="test",
    )
    stuck_path = tmp_path / "stuck.bin"
    stuck_path.write_bytes(b"y" * 100)
    stuck = repository.register_artifact(
        session_id="s",
        kind="dump",
        path=str(stuck_path),
        sha256="b",
        source="test",
    )
    newest_path = tmp_path / "newest.bin"
    newest_path.write_bytes(b"z" * 100)
    repository.register_artifact(
        session_id="s",
        kind="dump",
        path=str(newest_path),
        sha256="c",
        source="test",
    )

    original_unlink = Path.unlink

    def refuse_stuck(self: Path, missing_ok: bool = False) -> None:
        if self == stuck_path:
            raise OSError("locked by another process")
        original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse_stuck)
    report = repository.gc_artifacts(max_total_bytes=1)

    assert report["removed"] == [vanished["id"]]
    assert [entry["id"] for entry in report["skipped"]] == [stuck["id"]]
    assert stuck_path.exists()
    assert newest_path.exists()


def test_gc_stops_once_usage_fits_the_budget(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    for name in ("one.bin", "two.bin"):
        target = tmp_path / name
        target.write_bytes(b"x" * 10)
        repository.register_artifact(
            session_id="s",
            kind="dump",
            path=str(target),
            sha256=name,
            source="test",
        )

    report = repository.gc_artifacts(max_total_bytes=1024)

    assert report["removed"] == []
    assert report["skipped"] == []
    assert (tmp_path / "one.bin").exists()


def test_append_audit_keeps_only_the_newest_retained_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(repository_module, "AUDIT_RETAINED_ROWS", 2)
    repository = InMemoryAnalysisRepository(tmp_path)
    for index in range(3):
        repository.append_audit(
            session_id="s",
            action=f"action.{index}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    entries = repository.list_audit()["entries"]
    assert isinstance(entries, list)
    assert sorted(item["action"] for item in entries) == ["action.1", "action.2"]


def test_list_audit_filters_by_session(tmp_path: Path) -> None:
    repository = InMemoryAnalysisRepository(tmp_path)
    for sid in ("s1", "s2"):
        repository.append_audit(
            session_id=sid,
            action="probe",
            params_summary={},
            ok=True,
            result_summary={},
        )

    everything = repository.list_audit()
    assert everything["total"] == 2
    only_s2 = repository.list_audit("s2")["entries"]
    assert isinstance(only_s2, list)
    assert [item["session_id"] for item in only_s2] == ["s2"]
