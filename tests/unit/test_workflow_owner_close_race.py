"""A workflow store landing after close must not resurrect cleared state.

Workflow operations hold runtime.lock, not the service lock, and a debugger
transition blocks for its full timeout inside that window. close_session does
not need runtime.lock to pop the runtime and clear the workflow owner, so it
can land mid-transition; the unconditional put that used to follow re-installed
the WorkflowRuntime for a session that never reopens -- one retained entry per
lost race, the very leak clear() exists to prevent.
"""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.workflows.engine import prepare_workflow_reset
from headless_re_mcp.workflows.runtime import WorkflowRunStatus, create_workflow_runtime


def _write_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    image[optional + 56 : optional + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)


class _FakeWorker:
    pid = 4242
    capabilities: tuple[str, ...] = ()

    def close(self) -> None: ...

    def terminate(self) -> None: ...


class _FakeRuntime:
    """Just enough runtime for close_session's worker-close loop."""

    def __init__(self) -> None:
        self.lock = RLock()
        self.worker = _FakeWorker()
        self.event_drain_pump = None
        self.event_log = None


def _fake_runtime() -> Any:
    return _FakeRuntime()


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def test_a_transition_finishing_after_close_does_not_resurrect_state(
    tmp_path: Path,
) -> None:
    """The transition's store must lose to close's clear, not undo it."""
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        runtime = _fake_runtime()
        service._runtime_owner.begin_open(session_id, BackendKind.X64DBG)
        service._runtime_owner.put(session_id, BackendKind.X64DBG, runtime)
        workflow = create_workflow_runtime(cursor=0)
        service._workflow_owner.put(session_id, workflow)

        # The operation fetched its workflow and prepared the transition, then
        # close popped the runtime and cleared the owner underneath it. A
        # fresh workflow's reset transition executes zero debugger commands,
        # so the fake runtime carries it.
        transition = prepare_workflow_reset(workflow.state)
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        assert service._workflow_owner.get(session_id) is None

        service._execute_workflow_transition_locked(
            session_id,
            runtime,
            workflow,
            transition,
            timeout=5.0,
        )

        assert service._workflow_owner.get(session_id) is None
        assert service._workflow_owner.get_terminal(session_id) is None
    finally:
        service.close_all()


def test_a_late_transition_does_not_clobber_the_terminal_snapshot(
    tmp_path: Path,
) -> None:
    """_fail_runtime's terminal record must survive a racing live put.

    WorkflowStateOwner.put moves an entry back to live and pops terminal, so a
    transition finishing after _fail_runtime recorded the failure used to erase
    the very snapshot workflow.status serves once the runtime is gone.
    """
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        runtime = _fake_runtime()
        service._runtime_owner.begin_open(session_id, BackendKind.X64DBG)
        service._runtime_owner.put(session_id, BackendKind.X64DBG, runtime)
        workflow = create_workflow_runtime(cursor=0)
        service._workflow_owner.put(session_id, workflow)
        transition = prepare_workflow_reset(workflow.state)

        service._fail_runtime(session_id, BackendKind.X64DBG, failure=RuntimeError("boom"))
        terminal = service._workflow_owner.get_terminal(session_id)
        assert terminal is not None
        assert terminal.status is WorkflowRunStatus.FAILED

        # The in-flight transition completes only now; its runtime is stale.
        service._execute_workflow_transition_locked(
            session_id,
            runtime,
            workflow,
            transition,
            timeout=5.0,
        )

        assert service._workflow_owner.get(session_id) is None
        assert service._workflow_owner.get_terminal(session_id) is terminal
    finally:
        service.close_all()
