"""Direct-call coverage for the workflow-locked helpers on ``AnalysisService``.

The ``workflow.navigate`` state machine reaches ``_workflow_resume_locked``,
``_workflow_ensure_paused_locked`` and ``_workflow_apply_breakpoint_locked``
through the workflow transition port, which makes their guard arms
(idle/running run-control, breakpoint-list recovery, capability checks) hard to
reach end to end. They only need a session with an open dynamic runtime and a
worker whose ``debug.state``/``breakpoints.*`` replies we can script, so this
file drives them directly against the runtime returned by ``_runtime``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService, JsonObject, _BackendRuntime
from headless_re_mcp.workflows.breakpoints import (
    BreakpointOperation,
    BreakpointOperationKind,
)
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _state,
    _write_minimal_pe,
)


class _ScriptWorker(FakeDynamicWorker):
    """A dynamic worker whose run-control replies and capabilities are scripted."""

    def __init__(
        self,
        *,
        caps: frozenset[str] | None = None,
        pause_reply: JsonObject | None = None,
        remove_error: XdbgRpcError | None = None,
        set_error: XdbgRpcError | None = None,
        breakpoint_list: JsonObject | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._caps = caps
        self._pause_reply = pause_reply
        self._remove_error = remove_error
        self._set_error = set_error
        self._breakpoint_list = breakpoint_list

    @property
    def capabilities(self) -> frozenset[str]:
        if self._caps is not None:
            return self._caps
        return super().capabilities

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "debug.pause" and self._pause_reply is not None:
            self.requests.append((command, params or {}))
            return dict(self._pause_reply)
        if command == "breakpoints.remove" and self._remove_error is not None:
            self.requests.append((command, params or {}))
            raise self._remove_error
        if command == "breakpoints.set" and self._set_error is not None:
            self.requests.append((command, params or {}))
            raise self._set_error
        if command == "breakpoints.list" and self._breakpoint_list is not None:
            self.requests.append((command, params or {}))
            return dict(self._breakpoint_list)
        return super().request(command, params, timeout=timeout)


def _dynamic_runtime(
    tmp_path: Path, worker: FakeDynamicWorker
) -> tuple[AnalysisService, str, _BackendRuntime]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    runtime = service._runtime(session_id, BackendKind.X64DBG)
    return service, session_id, runtime


# --- _workflow_resume_locked ----------------------------------------------------


def test_resume_locked_returns_early_when_already_running(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("running")

    service._workflow_resume_locked(session_id, runtime, timeout=5.0)

    assert ("debug.resume", {}) not in worker.requests


def test_resume_locked_rejects_a_target_that_is_neither_running_nor_paused(
    tmp_path: Path,
) -> None:
    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("idle")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_resume_locked(session_id, runtime, timeout=5.0)

    assert exc.value.code == "not_debugging"


# --- _workflow_ensure_paused_locked ---------------------------------------------


def test_ensure_paused_raises_when_the_pause_shows_the_target_gone(
    tmp_path: Path,
) -> None:
    # debug.pause reports a non-debugging state: the debuggee exited while the
    # workflow was pausing it, so ensure_paused must refuse rather than pretend.
    worker = _ScriptWorker(pause_reply=_state("idle"))
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("running")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_ensure_paused_locked(session_id, runtime, timeout=5.0)

    assert exc.value.code == "not_debugging"


# --- _workflow_apply_breakpoint_locked ------------------------------------------


def _set_op(address: int) -> BreakpointOperation:
    return BreakpointOperation(
        kind=BreakpointOperationKind.SET,
        intent_id="i1",
        address=address,
        module_revision=0,
    )


def _remove_op(address: int) -> BreakpointOperation:
    return BreakpointOperation(
        kind=BreakpointOperationKind.REMOVE,
        intent_id="i1",
        address=address,
        module_revision=0,
    )


def test_apply_breakpoint_removal_while_idle_is_a_noop(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("idle")

    service._workflow_apply_breakpoint_locked(
        session_id, runtime, _remove_op(0x140001000), timeout=5.0
    )

    assert ("breakpoints.remove", {"address": 0x140001000}) not in worker.requests


def test_apply_breakpoint_set_while_idle_is_refused(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("idle")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_apply_breakpoint_locked(
            session_id, runtime, _set_op(0x140001000), timeout=5.0
        )

    assert exc.value.code == "not_debugging"


def test_apply_breakpoint_pauses_a_running_target_first(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("running")

    service._workflow_apply_breakpoint_locked(
        session_id, runtime, _set_op(0x140001000), timeout=5.0
    )

    commands = [command for command, _ in worker.requests]
    assert "debug.pause" in commands
    assert "breakpoints.set" in commands


def test_apply_breakpoint_reraises_a_non_removal_command_failure(tmp_path: Path) -> None:
    worker = _ScriptWorker(set_error=XdbgRpcError("backend_error", "set exploded"))
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("paused")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_apply_breakpoint_locked(
            session_id, runtime, _set_op(0x140001000), timeout=5.0
        )

    assert exc.value.code == "backend_error"


def test_removal_command_failure_recovers_when_no_breakpoint_remains(
    tmp_path: Path,
) -> None:
    # A REMOVE that fails with debugger_command_failed is absorbed when the
    # breakpoint is no longer listed. A non-matching entry exercises the
    # loop-continue arc before the removal is treated as already done.
    worker = _ScriptWorker(
        remove_error=XdbgRpcError("debugger_command_failed", "no such bp"),
        breakpoint_list={
            "breakpoints": [
                {"address": 0x140009999, "type": "software"},
            ],
            "count": 1,
        },
    )
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("paused")

    service._workflow_apply_breakpoint_locked(
        session_id, runtime, _remove_op(0x140001000), timeout=5.0
    )

    commands = [command for command, _ in worker.requests]
    assert "breakpoints.list" in commands


def test_removal_command_failure_reraises_when_the_breakpoint_is_still_present(
    tmp_path: Path,
) -> None:
    worker = _ScriptWorker(
        remove_error=XdbgRpcError("debugger_command_failed", "still there"),
        breakpoint_list={
            "breakpoints": [
                {"address": 0x140001000, "type": "software"},
            ],
            "count": 1,
        },
    )
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("paused")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_apply_breakpoint_locked(
            session_id, runtime, _remove_op(0x140001000), timeout=5.0
        )

    assert exc.value.code == "debugger_command_failed"


def test_removal_recovery_rejects_a_non_list_breakpoint_payload(tmp_path: Path) -> None:
    worker = _ScriptWorker(
        remove_error=XdbgRpcError("debugger_command_failed", "gone"),
        breakpoint_list={"breakpoints": "not-a-list", "count": 0},
    )
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("paused")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_apply_breakpoint_locked(
            session_id, runtime, _remove_op(0x140001000), timeout=5.0
        )

    assert exc.value.code == "rpc_protocol_error"


def test_removal_recovery_rejects_a_non_dict_breakpoint_entry(tmp_path: Path) -> None:
    worker = _ScriptWorker(
        remove_error=XdbgRpcError("debugger_command_failed", "gone"),
        breakpoint_list={"breakpoints": ["not-a-dict"], "count": 1},
    )
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("paused")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_apply_breakpoint_locked(
            session_id, runtime, _remove_op(0x140001000), timeout=5.0
        )

    assert exc.value.code == "rpc_protocol_error"


def test_removal_recovery_rejects_a_breakpoint_without_an_int_address(
    tmp_path: Path,
) -> None:
    worker = _ScriptWorker(
        remove_error=XdbgRpcError("debugger_command_failed", "gone"),
        breakpoint_list={
            "breakpoints": [{"address": "0x1000", "type": "software"}],
            "count": 1,
        },
    )
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)
    worker.current_state = _state("paused")

    with pytest.raises(XdbgRpcError) as exc:
        service._workflow_apply_breakpoint_locked(
            session_id, runtime, _remove_op(0x140001000), timeout=5.0
        )

    assert exc.value.code == "rpc_protocol_error"


# --- _workflow_refresh_modules_locked -------------------------------------------


def test_refresh_modules_maps_a_missing_module_to_none(tmp_path: Path) -> None:
    from headless_re_mcp.core.models import ModuleSelector

    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)

    resolved = service._workflow_refresh_modules_locked(
        session_id,
        runtime,
        {"ghost": ModuleSelector(base=0xDEAD0000)},
        timeout=5.0,
    )

    assert resolved == {"ghost": None}


def test_refresh_modules_reraises_a_non_missing_address_error(tmp_path: Path) -> None:
    from headless_re_mcp.core.addressing import AddressSyncError
    from headless_re_mcp.core.models import ModuleSelector

    worker = _ScriptWorker()
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AddressSyncError("module_identity_mismatch", "hash drift")

    import headless_re_mcp.core.service as service_mod

    original = service_mod.build_rebased_module_mapping
    service_mod.build_rebased_module_mapping = boom  # type: ignore[assignment]
    try:
        with pytest.raises(AddressSyncError) as exc:
            service._workflow_refresh_modules_locked(
                session_id,
                runtime,
                {"main": ModuleSelector(base=0x140000000)},
                timeout=5.0,
            )
    finally:
        service_mod.build_rebased_module_mapping = original  # type: ignore[assignment]

    assert exc.value.code == "module_identity_mismatch"


# --- _require_workflow_capability -----------------------------------------------


def test_require_workflow_capability_rejects_a_missing_capability(tmp_path: Path) -> None:
    worker = _ScriptWorker(caps=frozenset({"debug.state"}))
    service, session_id, runtime = _dynamic_runtime(tmp_path, worker)

    with pytest.raises(XdbgRpcError) as exc:
        service._require_workflow_capability(runtime, "modules.list")

    assert exc.value.code == "capability_unavailable"
    assert exc.value.details["capability"] == "modules.list"


# --- small workflow guards ------------------------------------------------------


def test_require_event_cursor_rejects_a_runtime_without_one(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, _session_id, _runtime = _dynamic_runtime(tmp_path, worker)
    bare = _BackendRuntime(worker)  # event_cursor defaults to None

    with pytest.raises(XdbgRpcError) as exc:
        service._require_event_cursor(bare)

    assert exc.value.code == "rpc_protocol_error"


def test_require_workflow_rejects_a_session_without_workflow_state(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, _session_id, _runtime = _dynamic_runtime(tmp_path, worker)

    with pytest.raises(XdbgRpcError) as exc:
        service._require_workflow("no-such-session")

    assert exc.value.code == "rpc_protocol_error"


def test_navigation_is_waiting_is_false_without_a_workflow(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, _session_id, _runtime = _dynamic_runtime(tmp_path, worker)

    assert service._workflow_navigation_is_waiting("no-such-session") is False


# --- _absorb_redundant_run_control ----------------------------------------------


def test_absorb_reraises_when_wait_for_does_not_include_paused() -> None:
    worker = FakeDynamicWorker()
    failure = XdbgRpcError("debugger_command_failed", "already paused")

    with pytest.raises(XdbgRpcError) as exc:
        AnalysisService._absorb_redundant_run_control(
            worker, "debug.pause", {"running"}, failure, 5.0
        )

    assert exc.value is failure


def test_absorb_reraises_the_original_when_the_state_probe_fails() -> None:
    class _ProbeFails(FakeDynamicWorker):
        def request(
            self,
            command: str,
            params: JsonObject | None = None,
            *,
            timeout: float = 120.0,
        ) -> JsonObject:
            if command == "debug.state":
                raise XdbgRpcError("rpc_transport_error", "probe blew up")
            return super().request(command, params, timeout=timeout)

    worker = _ProbeFails()
    failure = XdbgRpcError("debugger_command_failed", "pause rejected")

    with pytest.raises(XdbgRpcError) as exc:
        AnalysisService._absorb_redundant_run_control(
            worker, "debug.pause", {"paused"}, failure, 5.0
        )

    assert exc.value is failure


# --- _annotate_debuggee_pids ----------------------------------------------------


def test_annotate_debuggee_pids_records_a_live_process(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, session_id, _runtime = _dynamic_runtime(tmp_path, worker)

    annotated = service._annotate_debuggee_pids(session_id, _state("paused"))

    assert annotated["debuggee_pid"] == 7100


def test_annotate_debuggee_pids_leaves_the_pid_absent_when_idle(tmp_path: Path) -> None:
    worker = _ScriptWorker()
    service, session_id, _runtime = _dynamic_runtime(tmp_path, worker)

    annotated = service._annotate_debuggee_pids(session_id, {"state": "idle"})

    assert annotated.get("debuggee_pid") is None
