from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind, Result
from headless_re_mcp.core.repository import (
    AnalysisRepository,
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.runtime_state import (
    BackendRuntimeOwner,
    BackendRuntimePhase,
    TraceStateOwner,
    UnpackStateOwner,
    WorkflowStateOwner,
)
from headless_re_mcp.core.service import AnalysisService


def test_backend_runtime_owner_enforces_transitions_and_terminal_reopen() -> None:
    owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()
    runtime = object()

    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.ABSENT
    with pytest.raises(RuntimeError):
        owner.put("s", BackendKind.IDA, runtime)

    owner.begin_open("s", BackendKind.IDA)
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.OPENING
    with pytest.raises(RuntimeError):
        owner.begin_open("s", BackendKind.IDA)
    owner.put("s", BackendKind.IDA, runtime)
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.READY
    assert owner.is_current("s", BackendKind.IDA, runtime)

    assert owner.fail("s", BackendKind.IDA) is runtime
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.FAILED
    assert owner.get("s", BackendKind.IDA) is None

    owner.begin_open("s", BackendKind.IDA)
    replacement = object()
    owner.put("s", BackendKind.IDA, replacement)
    assert owner.pop("s", BackendKind.IDA) is replacement
    assert owner.phase("s", BackendKind.IDA) is BackendRuntimePhase.CLOSED


def test_backend_runtime_owner_serializes_concurrent_open() -> None:
    owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()

    def begin() -> bool:
        try:
            owner.begin_open("s", BackendKind.X64DBG)
        except RuntimeError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: begin(), range(32)))
    assert outcomes.count(True) == 1
    assert owner.phase("s", BackendKind.X64DBG) is BackendRuntimePhase.OPENING


def test_workflow_unpack_and_trace_owners_keep_independent_terminal_state() -> None:
    workflows: WorkflowStateOwner[str] = WorkflowStateOwner()
    workflows.put("s", "active")
    assert workflows.fail_live("s", lambda value: f"failed:{value}") == "failed:active"
    workflows.put_terminal("s", "cancelled")
    assert workflows.get("s") is None
    assert workflows.get_terminal("s") == "cancelled"

    unpack: UnpackStateOwner[str] = UnpackStateOwner()
    unpack.put("s", "running")
    unpack.put_protection_snapshot("s", [{"base": 1}])
    copied = unpack.get_protection_snapshot("s")
    assert copied == [{"base": 1}]
    assert copied is not unpack.protection_snapshots["s"]
    unpack.clear("s")
    assert not unpack.contains("s")

    traces: TraceStateOwner[str] = TraceStateOwner()

    def claim(value: str) -> str | None:
        return traces.put_if_inactive("s", value, is_active=lambda _: True)

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(claim, [f"trace-{i}" for i in range(16)]))
    assert claims.count(None) == 1
    assert sum(item is not None for item in claims) == 15


def test_state_owners_tolerate_absent_keys() -> None:
    # pop of a runtime that was never opened must leave it ABSENT, not CLOSED:
    # a spurious CLOSED would make a later begin_open look like a reopen.
    runtimes: BackendRuntimeOwner[object] = BackendRuntimeOwner()
    assert runtimes.pop("ghost", BackendKind.IDA) is None
    assert runtimes.phase("ghost", BackendKind.IDA) is BackendRuntimePhase.ABSENT

    workflows: WorkflowStateOwner[str] = WorkflowStateOwner()
    # Failing a session with no live workflow is a no-op that returns nothing.
    assert workflows.fail_live("ghost", lambda value: value) is None
    # clear_terminal drops the record and is idempotent when there is none.
    workflows.put_terminal("s", "done")
    workflows.clear_terminal("s")
    assert workflows.get_terminal("s") is None
    workflows.clear_terminal("s")


@pytest.fixture(params=["memory", "sqlite"])
def repository(request: pytest.FixtureRequest, tmp_path: Path) -> AnalysisRepository:
    root = tmp_path / str(request.param)
    if request.param == "memory":
        return InMemoryAnalysisRepository(root)
    return SqliteAnalysisRepository(root)


def test_analysis_repository_contract(repository: AnalysisRepository, tmp_path: Path) -> None:
    session_id = "session-contract"
    created = Result[dict[str, object]](
        ok=True,
        data={
            "session": {
                "id": session_id,
                "binary": "fixture.exe",
                "sha256": "a" * 64,
                "architecture": "x64",
                "state": "created",
            }
        },
    )
    repository.note_session_created("fixture.exe", created)
    unclean, unclean_total = repository.list_unclean_sessions()
    assert [item["id"] for item in unclean] == [session_id]
    assert unclean_total == 1

    repository.record_backend(
        session_id,
        "ida",
        worker_id="ida:1",
        pid=123,
        endpoint="stdio://pid/123",
    )
    assert repository.list_backends(session_id) == [
        {
            "session_id": session_id,
            "kind": "ida",
            "worker_id": "ida:1",
            "pid": 123,
            "endpoint": "stdio://pid/123",
        }
    ]

    artifact_path = tmp_path / "artifact.bin"
    artifact_path.write_bytes(b"contract")
    artifact = repository.register_artifact(
        session_id=session_id,
        kind="dump",
        path=artifact_path,
        sha256="b" * 64,
        source="contract",
    )
    assert repository.describe_artifact(str(artifact["id"])) == artifact
    listed = repository.list_artifacts(session_id)
    assert listed["count"] == 1
    assert listed["artifacts"][0]["id"] == artifact["id"]

    repository.append_timeline(session_id, "contract.event", "recorded", value=7)
    timeline = repository.list_timeline(session_id)
    assert [item["event"] for item in timeline["events"]] == [
        "session.created",
        "contract.event",
    ]

    repository.append_audit(
        session_id=session_id,
        action="contract.audit",
        params_summary={"access_token": "do-not-store", "safe": 7},
        ok=True,
        result_summary={"done": True},
    )
    entries = repository.list_audit(session_id)["entries"]
    contract_entry = next(item for item in entries if item["action"] == "contract.audit")
    assert contract_entry["params_summary"] == {"access_token": "***", "safe": 7}

    written: list[Path] = []

    def write_unpack(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "state.json").write_text("{}", encoding="utf-8")
        written.append(directory)

    repository.persist_unpack_state(session_id, write=write_unpack)
    assert written and (written[0] / "state.json").is_file()

    repository.note_session_closed(
        session_id,
        None,
        Result(ok=True, data={"closed": True}),
    )
    assert repository.list_unclean_sessions() == ([], 0)


def test_the_audit_log_is_trimmed_to_the_newest_entries(tmp_path: Path) -> None:
    """The audit table is the one store with no natural end.

    Sessions and artifacts are bounded by what the operator opens and by
    artifacts.gc, but a server that runs for months appends audit rows forever,
    and list_audit counts the whole table on every page.
    """
    repository = SqliteAnalysisRepository(tmp_path / "audit-quota")
    store = repository.store
    store.audit_retained_rows = 5
    store.audit_trim_interval = 4

    for index in range(12):
        repository.append_audit(
            session_id="s1",
            action=f"action-{index:02d}",
            params_summary={},
            ok=True,
            result_summary={},
        )

    listed = repository.list_audit("s1", limit=50)
    actions = [entry["action"] for entry in listed["entries"]]
    # Trimming is amortised over a batch, so the bound is approximate; what has
    # to hold is that it stops growing and keeps the newest rows.
    assert len(actions) <= store.audit_retained_rows + store.audit_trim_interval
    assert actions[0] == "action-11"
    assert listed["total"] == len(actions)


def test_cleanly_closed_sessions_are_dropped_and_unclean_ones_are_not(tmp_path: Path) -> None:
    """The in-memory registry keeps 64 closed sessions; sqlite kept every one.

    Measured at 800 closed rows: 225 KB and still climbing, plus every
    knowledge fact those sessions recorded. sessions.unclean is how an
    operator finds work that was open when the process died, so those rows
    stay.
    """
    repository = SqliteAnalysisRepository(tmp_path / "closed-quota")
    store = repository.store
    store.retained_closed_sessions = 3

    store.upsert_session(
        session_id="live",
        binary="live.exe",
        sha256="aa" * 32,
        architecture="x86_64",
        state="ready",
        closed_cleanly=False,
    )
    store.upsert_session(
        session_id="crash",
        binary="crash.exe",
        sha256="bb" * 32,
        architecture="x86_64",
        state="failed",
        closed_cleanly=False,
    )
    store.record_knowledge(session_id="live", kind="function", key="keep", value={})
    for index in range(6):
        sid = f"closed-{index}"
        store.upsert_session(
            session_id=sid,
            binary=f"{sid}.exe",
            sha256="cc" * 32,
            architecture="x86_64",
            state="closed",
            closed_cleanly=True,
        )
        store.record_knowledge(session_id=sid, kind="function", key="fact", value={"n": index})

    assert store.get_session("live") is not None
    assert store.get_session("crash") is not None
    remaining_closed = [
        sid
        for sid in (f"closed-{index}" for index in range(6))
        if store.get_session(sid) is not None
    ]
    assert remaining_closed == ["closed-3", "closed-4", "closed-5"]
    assert store.list_knowledge("live")["total"] == 1
    assert store.list_knowledge("closed-0")["total"] == 0
    assert store.list_knowledge("closed-5")["total"] == 1
    unclean, total = store.list_unclean_sessions()
    assert total == 2
    assert {row["id"] for row in unclean} == {"live", "crash"}


def test_dropping_a_closed_session_removes_its_timeline_too(tmp_path: Path) -> None:
    """Sqlite row trim left sessions/<id>/timeline.jsonl behind.

    Measured at 250 closed sessions: 250 directories and 60 KB of timeline
    still on disk after the rows were gone. A disk-usage walk then visits
    every one for the life of the artifact root.
    """
    root = tmp_path / "timeline-quota"
    repository = SqliteAnalysisRepository(root)
    repository.store.retained_closed_sessions = 2
    for index in range(5):
        sid = f"closed-{index}"
        repository.note_session_created(
            "t.exe",
            Result(
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
            ),
        )
        repository.note_session_closed(sid, None, Result(ok=True, data={"closed": True}))

    sessions = root / "sessions"
    remaining = (
        sorted(path.name for path in sessions.iterdir() if path.is_dir())
        if sessions.exists()
        else []
    )
    assert remaining == ["closed-3", "closed-4"]
    assert not (sessions / "closed-0" / "timeline.jsonl").exists()
    assert (sessions / "closed-4" / "timeline.jsonl").is_file()


def test_inmemory_trim_forgets_the_dropped_session_timeline(tmp_path: Path) -> None:
    """InMemory trim unlinked a file it never wrote and left events in RAM."""
    repository = InMemoryAnalysisRepository(tmp_path)
    repository.retained_closed_sessions = 2
    for index in range(5):
        sid = f"closed-{index}"
        repository.note_session_created(
            "t.exe",
            Result(
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
            ),
        )
        repository.append_timeline(sid, "contract.event", "recorded", value=index)
        repository.note_session_closed(sid, None, Result(ok=True, data={"closed": True}))

    assert repository.list_timeline("closed-0")["total"] == 0
    assert repository.list_timeline("closed-4")["total"] >= 1


def test_sqlite_trim_skips_a_traversing_session_id_instead_of_failing_the_close(
    tmp_path: Path,
) -> None:
    """A poisoned ``..`` row must not break the trim, and must delete nothing.

    A stored id is normally a uuid, but the trim guarded its file cleanup with
    ``Path(id).name != id`` alone, which ``..`` passes -- and
    ``<root>/debug-events/..`` is the artifact root itself, so the cleanup
    rmtree pointed at everything the service owns, this database included.
    ``session_timeline_path`` refused the id first, so what actually shipped
    was the other failure: the ValueError raised out of ``upsert_session`` and
    rolled back the close, so one poisoned row failed every later clean close
    for the life of the database. Hostile ids must be skipped: trimmed from
    the table, no exception, nothing outside their own directories touched.
    """
    root = tmp_path / "poisoned-sqlite"
    repository = SqliteAnalysisRepository(root)
    store = repository.store
    store.retained_closed_sessions = 1
    sentinel = root / "debug-events" / "innocent" / "events.jsonl"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep me", encoding="utf-8")
    for sid in ("..", "closed-a", "closed-b"):
        store.upsert_session(
            session_id=sid,
            binary="t.exe",
            sha256="dd" * 32,
            architecture="x86_64",
            state="closed",
            closed_cleanly=True,
        )
    assert store.get_session("..") is None, "the poisoned row must still be trimmed"
    assert sentinel.read_text(encoding="utf-8") == "keep me"
    assert store.db_path.is_file(), "an escaping rmtree would have taken the database"


def test_inmemory_trim_skips_a_traversing_session_id_instead_of_failing_the_close(
    tmp_path: Path,
) -> None:
    """The in-memory trim had the same hole: closing past the retention limit
    with a ``..`` row stored raised ValueError out of note_session_closed."""
    root = tmp_path / "poisoned-memory"
    repository = InMemoryAnalysisRepository(root)
    repository.retained_closed_sessions = 1
    sentinel = root / "debug-events" / "innocent" / "events.jsonl"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep me", encoding="utf-8")
    for sid in ("..", "closed-a", "closed-b"):
        repository.note_session_created(
            "t.exe",
            Result(
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
            ),
        )
        repository.note_session_closed(sid, None, Result(ok=True, data={"closed": True}))
    assert sentinel.read_text(encoding="utf-8") == "keep me"
    assert repository.list_timeline("closed-b")["total"] >= 1


def test_inmemory_gc_does_not_delete_the_newest_artifact(tmp_path: Path) -> None:
    """SQLite skips the newest file; InMemory used to collect it immediately."""
    repository = InMemoryAnalysisRepository(tmp_path)
    oldest = tmp_path / "old.bin"
    newest = tmp_path / "new.bin"
    oldest.write_bytes(b"O" * 64)
    newest.write_bytes(b"N" * 64)
    repository.register_artifact(
        session_id="s",
        kind="dump",
        path=oldest,
        sha256="1" * 64,
        source="test",
        size=64,
    )
    kept = repository.register_artifact(
        session_id="s",
        kind="dump",
        path=newest,
        sha256="2" * 64,
        source="test",
        size=64,
    )
    result = repository.gc_artifacts(max_total_bytes=1)
    assert kept["id"] not in result["removed"]
    assert newest.is_file()
    assert result["skipped_count"] == 0


def test_repository_gc_drops_untrusted_rows_without_unlinking_external_files(
    repository: AnalysisRepository, tmp_path: Path
) -> None:
    outside = tmp_path / "outside-artifact.bin"
    outside.write_bytes(b"outside")
    untrusted = repository.register_artifact(
        session_id="s",
        kind="dump",
        path=outside,
        sha256="1" * 64,
        source="test",
        size=outside.stat().st_size,
    )
    root = repository.artifact_root  # type: ignore[attr-defined]
    newest = root / "trace" / "s" / "newest.bin"
    newest.parent.mkdir(parents=True, exist_ok=True)
    newest.write_bytes(b"newest")
    repository.register_artifact(
        session_id="s",
        kind="dump",
        path=newest,
        sha256="2" * 64,
        source="test",
        size=newest.stat().st_size,
    )

    result = repository.gc_artifacts(max_total_bytes=1)

    assert outside.read_bytes() == b"outside"
    assert str(untrusted["id"]) in result["invalid_paths"]
    assert result["invalid_path_count"] == 1
    assert repository.describe_artifact(str(untrusted["id"])) is None
    assert newest.is_file()


@pytest.mark.parametrize("invalid", (None, True, "1024", 1.5, 0, -1))
def test_repository_gc_rejects_non_positive_or_non_integer_budgets(
    repository: AnalysisRepository, invalid: object
) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        repository.gc_artifacts(max_total_bytes=invalid)  # type: ignore[arg-type]


def _write_minimal_pe(path: Path, *, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


def test_analysis_service_accepts_repository_without_legacy_store(tmp_path: Path) -> None:
    fixture = tmp_path / "session-target.exe"
    _write_minimal_pe(fixture)
    settings = replace(Settings.load(), artifact_root=tmp_path / "service-artifacts")
    repository = InMemoryAnalysisRepository(settings.artifact_root)
    service = AnalysisService(settings, repository=repository)

    created = service.create_session(str(fixture))

    assert created.ok is True
    assert not hasattr(service, "_store")
    assert repository.list_unclean_sessions()[1] == 1
