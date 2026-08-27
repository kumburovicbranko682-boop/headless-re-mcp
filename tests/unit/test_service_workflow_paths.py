"""Path coverage for the workflow orchestration mixin (``core/service_workflow``).

The dynamic-service suite drives the common workflow flows, but the per-method
timeout guards, the module-untrack/refresh and breakpoint-list action bodies,
the intent/pattern validation raises, the navigate-to-breakpoint guards, and the
reset failure path were unreached. These reuse the ``FakeDynamicWorker`` harness:
guards that reject before any backend call run on an unopened service, while the
action bodies run against an opened, paused dynamic session.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import ModuleSelector
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _state,
    _write_minimal_pe,
)

_RUNTIME_BASE = 0x7FF800000000


def _bare(tmp_path: Path) -> AnalysisService:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    return _service(tmp_path, FakeDynamicWorker())


def _live(tmp_path: Path, *, module: bool = True) -> tuple[AnalysisService, str, FakeDynamicWorker]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    if module:
        payload = tmp_path / "payload.dll"
        _write_minimal_pe(payload, preferred_base=0x180000000, image_size=0x5000)
        worker = FakeDynamicWorker(
            module_name=payload.name,
            module_path=str(payload),
            module_base=_RUNTIME_BASE,
            module_size=0x5000,
        )
    else:
        worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id, worker


# --------------------------------------------------------------------------- #
# per-method timeout guards (reject before any backend call)                   #
# --------------------------------------------------------------------------- #
def test_workflow_methods_reject_an_invalid_timeout(tmp_path: Path) -> None:
    service = _bare(tmp_path)
    selector = ModuleSelector(name="payload.dll")
    for result in (
        service.workflow_reset("s1", timeout=0),
        service.workflow_cancel("s1", timeout=0),
        service.workflow_module_track("s1", "payload", selector, timeout=0),
        service.workflow_module_untrack("s1", "payload", timeout=0),
        service.workflow_module_refresh("s1", timeout=0),
        service.workflow_breakpoint_put("s1", "oep", "payload", 0x10, timeout=0),
        service.workflow_breakpoint_disable("s1", "oep", timeout=0),
        service.workflow_breakpoint_remove("s1", "oep", timeout=0),
        service.workflow_navigate_to_breakpoint("s1", "oep", timeout=0),
    ):
        assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------- #
# input validation that rejects before the action                             #
# --------------------------------------------------------------------------- #
def test_workflow_module_refresh_rejects_blank_or_duplicate_keys(tmp_path: Path) -> None:
    service = _bare(tmp_path)
    for keys in ([], [""], ["dup", "dup"]):
        result = service.workflow_module_refresh("s1", keys=keys)
        assert result.ok is False and result.error is not None


def test_workflow_breakpoint_put_rejects_an_invalid_intent(tmp_path: Path) -> None:
    service = _bare(tmp_path)
    result = service.workflow_breakpoint_put("s1", "oep", "payload", -1)
    assert result.ok is False and result.error is not None


def test_workflow_navigate_to_event_rejects_a_blank_kind(tmp_path: Path) -> None:
    service = _bare(tmp_path)
    result = service.workflow_navigate_to_event("s1", "")
    assert result.ok is False and result.error is not None


def test_workflow_navigate_to_breakpoint_rejects_an_out_of_range_budget(tmp_path: Path) -> None:
    service = _bare(tmp_path)
    result = service.workflow_navigate_to_breakpoint("s1", "oep", event_budget=0)
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------- #
# action bodies that need a live, paused workflow                              #
# --------------------------------------------------------------------------- #
def test_workflow_module_untrack_drops_a_tracked_module(tmp_path: Path) -> None:
    service, session_id, _ = _live(tmp_path)
    try:
        assert service.workflow_module_track(
            session_id, "payload", ModuleSelector(name="payload.dll")
        ).ok
        result = service.workflow_module_untrack(session_id, "payload")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["module_key"] == "payload"
    finally:
        assert service.close_session(session_id).ok


def test_workflow_module_refresh_runs_over_the_tracked_modules(tmp_path: Path) -> None:
    service, session_id, _ = _live(tmp_path)
    try:
        assert service.workflow_module_track(
            session_id, "payload", ModuleSelector(name="payload.dll")
        ).ok
        result = service.workflow_module_refresh(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert "workflow" in result.data
    finally:
        assert service.close_session(session_id).ok


def test_workflow_breakpoint_list_reports_the_intents(tmp_path: Path) -> None:
    service, session_id, _ = _live(tmp_path, module=False)
    try:
        assert service.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
        result = service.workflow_breakpoint_list(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert "breakpoints" in result.data
        assert result.data["status"]
    finally:
        assert service.close_session(session_id).ok


def test_workflow_navigate_to_breakpoint_refuses_an_unknown_intent(tmp_path: Path) -> None:
    service, session_id, _ = _live(tmp_path, module=False)
    try:
        result = service.workflow_navigate_to_breakpoint(session_id, "missing")
        assert result.ok is False and result.error is not None
    finally:
        assert service.close_session(session_id).ok


def test_workflow_navigate_to_breakpoint_refuses_a_disabled_intent(tmp_path: Path) -> None:
    service, session_id, _ = _live(tmp_path, module=False)
    try:
        assert service.workflow_breakpoint_put(
            session_id, "oep", "payload", 0x1234, enabled=False
        ).ok
        result = service.workflow_navigate_to_breakpoint(session_id, "oep")
        assert result.ok is False and result.error is not None
    finally:
        assert service.close_session(session_id).ok


def test_workflow_navigate_to_breakpoint_refuses_a_deferred_intent(tmp_path: Path) -> None:
    service, session_id, _ = _live(tmp_path, module=False)
    try:
        assert service.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
        result = service.workflow_navigate_to_breakpoint(session_id, "oep")
        assert result.ok is False and result.error is not None
    finally:
        assert service.close_session(session_id).ok


def test_workflow_reset_reports_a_failed_breakpoint_teardown(tmp_path: Path) -> None:
    service, session_id, worker = _live(tmp_path)
    try:
        assert service.workflow_module_track(
            session_id, "payload", ModuleSelector(name="payload.dll")
        ).ok
        assert service.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
        assert worker.breakpoint_addresses
        worker.breakpoint_removal_error = XdbgRpcError(
            "debugger_command_failed", "remove failed", retryable=True
        )
        result = service.workflow_reset(session_id)
        assert result.ok is False and result.error is not None
    finally:
        worker.breakpoint_removal_error = None
        assert service.close_session(session_id).ok
