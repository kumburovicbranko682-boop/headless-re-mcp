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
        sid for sid in (f"closed-{index}" for index in range(6)) if store.get_session(sid) is not None
    ]
    assert remaining_closed == ["closed-3", "closed-4", "closed-5"]
    assert store.list_knowledge("live")["total"] == 1
    assert store.list_knowledge("closed-0")["total"] == 0
    assert store.list_knowledge("closed-5")["total"] == 1
    unclean, total = store.list_unclean_sessions()
    assert total == 2
    assert {row["id"] for row in unclean} == {"live", "crash"}


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
