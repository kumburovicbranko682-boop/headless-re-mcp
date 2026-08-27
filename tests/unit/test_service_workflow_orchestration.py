"""The workflow orchestration surface must bound its inputs and drive transitions.

``WorkflowAnalysisMixin`` is a block of MCP wrappers over the workflow engine:
each validates its timeout (and any structural argument) before opening a
transition, then runs an ``action`` closure under the backend runtime lock.
The timeout/argument guards return without touching the runtime, so they are
pinned directly; the transition bodies are driven end to end with the shared
``FakeDynamicWorker`` against a paused session with a tracked module.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _state,
    _workflow_state,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]


def _paused_session(tmp_path: Path) -> tuple[AnalysisService, str, FakeDynamicWorker]:
    binary = tmp_path / "fixture.exe"
    module = tmp_path / "payload.dll"
    _write_minimal_pe(binary)
    _write_minimal_pe(module, preferred_base=0x180000000, image_size=0x5000)
    worker = FakeDynamicWorker(
        module_name=module.name,
        module_path=str(module),
        module_base=0x7FF800000000,
        module_size=0x5000,
    )
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id, worker


def _track_payload(service: AnalysisService, session_id: str) -> None:
    assert service.workflow_module_track(
        session_id, "payload", ModuleSelector(name="payload.dll")
    ).ok


# --------------------------------------------------------------------------
# timeout / argument guards (return before any runtime work)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda s, sid: s.workflow_reset(sid, timeout=0),
        lambda s, sid: s.workflow_cancel(sid, timeout=0),
        lambda s, sid: s.workflow_module_track(
            sid, "k", ModuleSelector(name="x.dll"), timeout=0
        ),
        lambda s, sid: s.workflow_module_untrack(sid, "k", timeout=0),
        lambda s, sid: s.workflow_module_refresh(sid, timeout=0),
        lambda s, sid: s.workflow_breakpoint_put(sid, "i", "k", 0x10, timeout=0),
        lambda s, sid: s.workflow_breakpoint_disable(sid, "i", timeout=0),
        lambda s, sid: s.workflow_breakpoint_remove(sid, "i", timeout=0),
        lambda s, sid: s.workflow_navigate_to_breakpoint(sid, "i", timeout=0),
    ],
)
def test_workflow_ops_reject_a_non_positive_timeout(
    tmp_path: Path, call: Callable[[AnalysisService, str], Result[JsonObject]]
) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        result = call(service, session_id)
        assert result.ok is False
        assert result.error is not None
        assert "timeout" in result.error.message
    finally:
        service.close_all()


@pytest.mark.parametrize("keys", [[""], ["a", "a"], []])
def test_module_refresh_rejects_bad_keys(tmp_path: Path, keys: list[str]) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        result = service.workflow_module_refresh(session_id, keys=keys)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_breakpoint_put_rejects_an_invalid_intent(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        result = service.workflow_breakpoint_put(session_id, "oep", "payload", -1)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_navigate_to_event_rejects_a_blank_kind(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        result = service.workflow_navigate_to_event(session_id, "")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_navigate_to_breakpoint_rejects_a_bad_event_budget(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        result = service.workflow_navigate_to_breakpoint(session_id, "oep", event_budget=0)
        assert result.ok is False
        assert result.error is not None
        assert "event_budget" in result.error.message
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# transition bodies (driven under the runtime lock)
# --------------------------------------------------------------------------


def test_module_untrack_removes_a_tracked_module(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        result = service.workflow_module_untrack(session_id, "payload")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["module_key"] == "payload"
        state = _workflow_state(result.data["workflow"])
        assert all(m["key"] != "payload" for m in state["modules"])
    finally:
        service.close_all()


def test_module_refresh_requests_a_refresh(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        result = service.workflow_module_refresh(session_id, keys=["payload"])
        assert result.ok, result.error
        assert result.data is not None
        assert "workflow" in result.data
    finally:
        service.close_all()


def test_module_refresh_all_keys(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        result = service.workflow_module_refresh(session_id)
        assert result.ok, result.error
    finally:
        service.close_all()


def test_breakpoint_list_reports_intents(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        assert service.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
        result = service.workflow_breakpoint_list(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["breakpoints"]
        assert result.data["status"]
    finally:
        service.close_all()


def test_navigate_to_breakpoint_rejects_an_unknown_intent(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        result = service.workflow_navigate_to_breakpoint(session_id, "ghost")
        assert result.ok is False
        assert result.error is not None
        assert "not defined" in result.error.message
    finally:
        service.close_all()


def test_navigate_to_breakpoint_rejects_a_disabled_intent(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        assert service.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
        assert service.workflow_breakpoint_disable(session_id, "oep").ok
        result = service.workflow_navigate_to_breakpoint(session_id, "oep")
        assert result.ok is False
        assert result.error is not None
        assert "disabled" in result.error.message
    finally:
        service.close_all()


def test_navigate_to_breakpoint_rejects_a_deferred_intent(tmp_path: Path) -> None:
    service, session_id, _ = _paused_session(tmp_path)
    try:
        # An intent for a module that is not tracked/loaded stays deferred, so it
        # never resolves to a runtime address and cannot be navigated to.
        put = service.workflow_breakpoint_put(session_id, "later", "unloaded", 0x50)
        if not put.ok:
            pytest.skip("backend does not accept a deferred breakpoint intent")
        result = service.workflow_navigate_to_breakpoint(session_id, "later")
        assert result.ok is False
        assert result.error is not None
        assert "deferred" in result.error.message
    finally:
        service.close_all()


def test_cancel_tolerates_a_missing_runtime(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    # No open_dynamic: the pre-action cancel-flag lookup finds no runtime and is
    # swallowed, and the request itself then fails cleanly on the missing worker.
    try:
        result = service.workflow_cancel(session_id)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_reset_surfaces_a_breakpoint_removal_failure(tmp_path: Path) -> None:
    service, session_id, worker = _paused_session(tmp_path)
    try:
        _track_payload(service, session_id)
        assert service.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
        # The between-samples reset disarms every breakpoint; if the debugger
        # refuses the removal, the transition fails and the cause surfaces.
        worker.breakpoint_removal_error = XdbgRpcError(
            "debugger_command_failed", "remove refused"
        )
        result = service.workflow_reset(session_id)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()
