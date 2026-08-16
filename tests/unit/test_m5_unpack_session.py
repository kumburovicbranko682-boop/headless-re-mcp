"""M5 unpack orchestration unit tests."""

from __future__ import annotations

import json
import struct
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.oep import score_oep_candidates
from headless_re_mcp.unpack.plan import build_unpack_plan
from headless_re_mcp.unpack.session import (
    UnpackArtifact,
    UnpackPhase,
    UnpackTimelineEvent,
    cancel_unpack_session,
    check_timeout,
    create_unpack_session,
    persist_state_snapshot,
    transition,
    write_timeline_jsonl,
)


def test_an_unwritable_timeline_copy_does_not_block_the_state_snapshot(
    tmp_path: Path,
) -> None:
    """The snapshot is what survives a restart; the JSONL is a convenience copy.

    Both are written from one step, the copy first, so a full volume failed
    there and the snapshot never ran -- the only durable record of the unpack,
    skipped because a redundant one could not be made. The step then reported
    failure for a dump that had already succeeded, and the in-memory state had
    advanced past what was on disk.
    """
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    state = create_unpack_session("abc123", route="upx", timeout_seconds=60)

    failure = write_timeline_jsonl(state, blocked / "timeline.jsonl")

    assert failure is not None, "an unwritable copy must be reported, not raised"

    snapshot = tmp_path / "session" / "state.json"
    persist_state_snapshot(state, snapshot)

    saved = json.loads(snapshot.read_text(encoding="utf-8"))
    assert saved["timeline"], "the snapshot carries the timeline the copy could not"
    assert saved["session_id"] == "abc123"


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    path.write_bytes(image)


def test_session_transitions_and_timeline(tmp_path: Path) -> None:
    state = create_unpack_session("sess1", route="generic_dynamic", input_sha256="aa")
    assert state.phase == UnpackPhase.DETECTED
    assert state.deadline_at is not None
    state = transition(
        state,
        UnpackPhase.RUNNING,
        event="run",
        message="running",
    )
    assert state.phase == UnpackPhase.RUNNING
    state = cancel_unpack_session(state)
    assert state.phase == UnpackPhase.CANCELLED
    assert state.timeline[-1].event == "cancelled"
    details = state.timeline[-1].details
    assert details["safe_rollback"] is False
    assert details["original_input_preserved"] is True
    assert details["artifacts_retained"] is True
    assert details["debuggee_paused_attempted"] is False
    assert all(item.to_dict()["claims_universal_unpack"] is False for item in state.timeline)


def test_check_timeout_transitions_to_failed() -> None:
    state = create_unpack_session("sess-timeout", route="generic_dynamic", timeout_seconds=30.0)
    assert state.deadline_at is not None
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    past = state.deadline_at + timedelta(seconds=1)
    timed = check_timeout(state, now=past)
    assert timed.phase == UnpackPhase.FAILED
    assert timed.failure is not None
    assert timed.failure.code == "unpack_timeout"
    assert timed.failure.retryable is True
    # Already terminal: further checks are no-ops.
    assert check_timeout(timed, now=past + timedelta(hours=1)) is timed


def test_check_timeout_ignores_before_deadline() -> None:
    state = create_unpack_session("sess-ok", route="upx", timeout_seconds=120.0)
    assert state.deadline_at is not None
    before = state.deadline_at - timedelta(seconds=1)
    assert check_timeout(state, now=before) is state


def test_cancel_honesty_flags() -> None:
    state = create_unpack_session("sess-cancel", route="bounded_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    cancelled = cancel_unpack_session(state, debuggee_paused_attempted=True)
    details = cancelled.timeline[-1].details
    assert details == {
        "original_input_preserved": True,
        "debuggee_paused_attempted": True,
        "artifacts_retained": True,
        "safe_rollback": False,
        "note": "cancel does not undo dumps or restore prior memory/file state",
    }


def test_oep_scoring_requires_multiple_signals_for_high_score() -> None:
    single = score_oep_candidates(
        module_base=0x140000000,
        module_size=0x4000,
        observations=[{"kind": "rip_in_main_module_code", "oep_rva": 0x1200}],
    )
    assert single[0]["score"] <= 0.45
    assert single[0]["authoritative"] is False

    multi = score_oep_candidates(
        module_base=0x140000000,
        module_size=0x4000,
        observations=[
            {"kind": "rip_in_main_module_code", "oep_rva": 0x1200},
            {"kind": "write_to_execute", "oep_rva": 0x1200},
            {"kind": "left_stub_region", "oep_rva": 0x1200},
            {"kind": "imports_resolved", "oep_rva": 0x1200},
        ],
        stub_rva_ranges=((0x1000, 0x100),),
    )
    assert multi[0]["oep_rva"] == 0x1200
    assert multi[0]["score"] > 0.45
    assert multi[0]["authoritative"] is False


def test_build_plan_routes() -> None:
    upx = build_unpack_plan(
        [{"category": "packer", "name": "UPX", "summary": "UPX", "confidence": 0.9}]
    )
    assert upx["route"] == "upx"
    assert upx["backend"] == "m3_upx"
    assert upx["claims_universal_unpack"] is False

    dotnet = build_unpack_plan([], pe_dotnet=True)
    assert dotnet["route"] == "dotnet"
    assert dotnet["backend"] == "m6_dotnet"


def test_service_unpack_plan_start_cancel(tmp_path: Path) -> None:
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]

    planned = service.unpack_plan(session_id, use_die=False)
    assert planned.ok and planned.data is not None
    assert planned.data["plan"]["route"] == "none"

    started = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert started.ok and started.data is not None
    assert started.data["unpack"]["phase"] == "detected"
    assert started.data["unpack"]["deadline_at"] is not None

    refused = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "unpack_already_active"

    status = service.unpack_status(session_id)
    assert status.ok
    cancelled = service.unpack_cancel(session_id)
    assert cancelled.ok
    assert cancelled.data["unpack"]["phase"] == "cancelled"
    assert cancelled.data["original_input_preserved"] is True
    assert cancelled.data["artifacts_retained"] is True
    assert cancelled.data["safe_rollback"] is False
    assert cancelled.data["debuggee_paused_attempted"] is False
    assert "does not undo dumps" in cancelled.data["note"]

    arts = service.unpack_artifacts(session_id)
    assert arts.ok
    # Artifacts ledger retained after cancel (input_binary still listed).
    assert arts.data["count"] >= 1
    assert arts.data["has_more"] is False
    timeline = Path(arts.data["timeline_path"])
    assert timeline.is_file()
    lines = timeline.read_text(encoding="utf-8").strip().splitlines()
    assert lines
    assert json.loads(lines[0])["claims_universal_unpack"] is False


def test_service_unpack_status_applies_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "timeout.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    state = create_unpack_session(session_id, route="generic_dynamic", timeout_seconds=10.0)
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    state = replace(state, deadline_at=datetime.now(UTC) - timedelta(seconds=5))
    service._store_unpack_session(state)

    status = service.unpack_status(session_id)
    assert status.ok and status.data is not None
    unpack = status.data["unpack"]
    assert unpack["phase"] == "failed"
    assert unpack["failure"]["code"] == "unpack_timeout"

    confirmed = service.unpack_confirm_oep(session_id, oep_rva=0x1500)
    assert not confirmed.ok
    assert confirmed.error is not None
    assert confirmed.error.code == "unpack_timeout"


def test_ensure_unpack_active_cooperative_timeout() -> None:
    from headless_re_mcp.unpack.session import ensure_unpack_active

    state = create_unpack_session("sess-preempt", route="generic_dynamic", timeout_seconds=30.0)
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    assert state.deadline_at is not None
    past = state.deadline_at + timedelta(seconds=1)
    timed, code = ensure_unpack_active(state, now=past, stage="dump_module")
    assert code == "unpack_timeout"
    assert timed.phase == UnpackPhase.FAILED
    assert any(item.event == "aborted_by_timeout" for item in timed.timeline)
    details = timed.timeline[-1].details
    assert details["safe_rollback"] is False
    assert details["partial_artifacts_retained"] is True
    assert details["aborted_stage"] == "dump_module"


def test_service_dump_blocked_after_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker

    worker = FakeDynamicWorker()
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        ),
        dynamic_worker_factory=lambda session, cfg: worker,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok
    state = create_unpack_session(session_id, route="generic_dynamic", timeout_seconds=10.0)
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    state = replace(state, deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    service._store_unpack_session(state)

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert not dumped.ok
    assert dumped.error is not None
    assert dumped.error.code == "unpack_timeout"
    assert dumped.data is None


def test_service_confirm_oep_flow(tmp_path: Path) -> None:
    binary = tmp_path / "packed.exe"
    _write_pe(binary)
    # Force generic route via fake recommendation path: add UPX-like? Use ASPack via
    # writing section names is hard; instead start with execute_upx=False after injecting
    # candidates through unpack_start on plain (route none), then manually store running.
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    service._store_unpack_session(state)

    scored = service.unpack_score_oep(
        session_id,
        module_base=0x140000000,
        module_size=0x4000,
        observations=[
            {"kind": "rip_in_main_module_code", "oep_rva": 0x1500},
            {"kind": "write_to_execute", "oep_rva": 0x1500},
        ],
    )
    assert scored.ok
    assert scored.data["authoritative"] is False
    assert scored.data["unpack"]["phase"] == "oep_candidate"

    confirmed = service.unpack_confirm_oep(session_id, oep_rva=0x1500)
    assert confirmed.ok
    assert confirmed.data["confirmed_oep_rva"] == 0x1500
    assert confirmed.data["unpack"]["confirmed_oep_rva"] == 0x1500


def test_service_score_oep_auto_collect_requires_dynamic_backend(tmp_path: Path) -> None:
    binary = tmp_path / "need-dyn.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    scored = service.unpack_score_oep(
        session_id,
        module_base=0x140000000,
        module_size=0x4000,
        observations=None,
    )
    assert not scored.ok
    assert scored.error is not None
    assert scored.error.code == "backend_unavailable"
    assert scored.data is None


def test_service_score_oep_auto_collects_from_fake_dynamic(tmp_path: Path) -> None:
    from tests.unit.test_dynamic_service import FakeDynamicWorker, _service, _write_minimal_pe

    binary = tmp_path / "auto-oep.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    # First snapshot establishes baseline; second call diffs protect + RIP.
    worker.current_state = {
        "debugging": True,
        "running": False,
        "state": "paused",
        "process_id": 7100,
        "thread_id": 7200,
    }
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    baseline = service.unpack_score_oep(
        session_id,
        module_base=0x140000000,
        module_size=0x4000,
        observations=None,
    )
    assert baseline.ok and baseline.data is not None
    assert baseline.data["auto_collected"] is True
    assert baseline.data["authoritative"] is False
    assert baseline.data["observation_count"] >= 1

    # Mutate region protect so write_to_execute can fire on next collect.
    previous = service._unpack_protect_snapshots[session_id]
    service._unpack_protect_snapshots[session_id] = [
        {**item, "protect": 0x04, "protect_name": "readwrite"} for item in previous
    ]
    scored = service.unpack_score_oep(
        session_id,
        module_base=0x140000000,
        module_size=0x4000,
        observations=None,
    )
    assert scored.ok and scored.data is not None
    assert scored.data["authoritative"] is False
    kinds = {item["kind"] for item in scored.data["observations"]}
    assert "rip_in_main_module_code" in kinds
    assert "write_to_execute" in kinds or "ep_section_protect_changed" in kinds


def test_unpack_artifacts_says_when_the_list_is_only_a_page(tmp_path: Path) -> None:
    """151 artifacts used to come back as count=151 with no has_more.

    The ledger grows for as long as the unpack runs. An agent reading count
    treated one reply as every dump the session produced.
    """
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    started = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert started.ok
    state = service._unpack_owner.get(session_id)
    assert state is not None
    extra = tuple(
        UnpackArtifact(
            kind="dump",
            path=f"/tmp/d{index}.bin",
            sha256="ab",
            phase=UnpackPhase.DUMPED,
        )
        for index in range(150)
    )
    service._unpack_owner.put(session_id, replace(state, artifacts=state.artifacts + extra))

    page = service.unpack_artifacts(session_id, offset=0, limit=100)
    assert page.ok and page.data is not None
    assert page.data["count"] == 100
    assert page.data["total"] == 151
    assert page.data["has_more"] is True
    assert len(page.data["artifacts"]) == 100

    tail = service.unpack_artifacts(session_id, offset=100, limit=100)
    assert tail.ok and tail.data is not None
    assert tail.data["count"] == 51
    assert tail.data["total"] == 151
    assert tail.data["has_more"] is False


def test_unpack_status_says_when_the_summary_is_only_a_window(tmp_path: Path) -> None:
    """151 artifacts and 202 timeline events used to come back in full.

    The tool calls itself a summary. The reply was the durable snapshot, so an
    agent treated one status as every dump and every step.
    """
    binary = tmp_path / "plain.exe"
    _write_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    started = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert started.ok
    state = service._unpack_owner.get(session_id)
    assert state is not None
    now = datetime.now(UTC)
    extra_arts = tuple(
        UnpackArtifact("dump", f"/tmp/d{index}.bin", "ab", UnpackPhase.DUMPED)
        for index in range(150)
    )
    extra_events = tuple(
        UnpackTimelineEvent(
            index + 10, now, UnpackPhase.RUNNING, "step", f"e{index}"
        )
        for index in range(200)
    )
    service._unpack_owner.put(
        session_id,
        replace(
            state,
            artifacts=state.artifacts + extra_arts,
            timeline=state.timeline + extra_events,
        ),
    )

    status = service.unpack_status(session_id)
    assert status.ok and status.data is not None
    unpack = status.data["unpack"]
    assert unpack["artifact_total"] == 151
    assert unpack["timeline_total"] == len(state.timeline) + 200
    assert len(unpack["artifacts"]) == 20
    assert len(unpack["timeline"]) == 50
    assert unpack["artifacts_has_more"] is True
    assert unpack["timeline_has_more"] is True
    assert unpack["artifacts"][-1]["path"] == "/tmp/d149.bin"
