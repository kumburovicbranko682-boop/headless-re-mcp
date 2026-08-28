"""Guards and action arms of the workflow orchestration wrappers.

WorkflowAnalysisMixin is the workflow surface of AnalysisService. The happy
navigation paths that need a live debugger are covered in test_dynamic_service
with a fake worker. This module covers the other arms:

- The timeout guard shared by every mutating call, which must reject a bad
  timeout before touching the backend.
- The per-call input guards (refresh keys, breakpoint intent invariants, event
  pattern, navigation budget) that fail before any action runs.
- A few action bodies that were otherwise unexercised (module untrack/refresh,
  breakpoint listing, and navigating to an intent that is missing or disabled),
  driven through the same fake-worker harness the dynamic tests use.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _state,
    _write_minimal_pe,
)


@pytest.fixture
def service(tmp_path: Path) -> tuple[AnalysisService, str]:
    """A PE session with no x64dbg open: enough for the pre-backend guards."""
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    svc = _service(tmp_path, FakeDynamicWorker())
    return svc, _create(svc, binary)


@pytest.fixture
def tracked(tmp_path: Path) -> tuple[AnalysisService, str]:
    """A paused session with one tracked module, so action bodies can run."""
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
    svc = _service(tmp_path, worker)
    session_id = _create(svc, binary)
    assert svc.open_dynamic(session_id).ok
    assert svc.workflow_module_track(session_id, "payload", ModuleSelector(name=module.name)).ok
    return svc, session_id


def _err(result: Result[JsonObject]) -> str:
    assert not result.ok and result.error is not None
    return result.error.code


# --- the shared timeout guard on every mutating call ------------------------

_TIMEOUT_GUARDED: list[tuple[str, Callable[[AnalysisService, str], Result[JsonObject]]]] = [
    ("reset", lambda s, sid: s.workflow_reset(sid, timeout=0)),
    ("cancel", lambda s, sid: s.workflow_cancel(sid, timeout=0)),
    (
        "module_track",
        lambda s, sid: s.workflow_module_track(sid, "k", ModuleSelector(name="x"), timeout=0),
    ),
    ("module_untrack", lambda s, sid: s.workflow_module_untrack(sid, "k", timeout=0)),
    ("module_refresh", lambda s, sid: s.workflow_module_refresh(sid, timeout=0)),
    ("breakpoint_put", lambda s, sid: s.workflow_breakpoint_put(sid, "i", "m", 0x10, timeout=0)),
    ("breakpoint_disable", lambda s, sid: s.workflow_breakpoint_disable(sid, "i", timeout=0)),
    ("breakpoint_remove", lambda s, sid: s.workflow_breakpoint_remove(sid, "i", timeout=0)),
    (
        "navigate_to_breakpoint",
        lambda s, sid: s.workflow_navigate_to_breakpoint(sid, "i", timeout=0),
    ),
]


@pytest.mark.parametrize("name,call", _TIMEOUT_GUARDED, ids=[name for name, _ in _TIMEOUT_GUARDED])
def test_a_bad_timeout_is_rejected_before_the_backend(
    service: tuple[AnalysisService, str],
    name: str,
    call: Callable[[AnalysisService, str], Result[JsonObject]],
) -> None:
    svc, session_id = service
    assert _err(call(svc, session_id)) == "invalid_request"


# --- per-call input guards, all before any action --------------------------


def test_cancel_without_a_runtime_swallows_the_signal_then_fails_backend(
    service: tuple[AnalysisService, str],
) -> None:
    """Cancel best-effort signals the runtime; with none open it must not raise.

    The signalling is wrapped so a missing runtime is ignored, and the action
    that follows is what reports the missing backend.
    """
    svc, session_id = service
    assert _err(svc.workflow_cancel(session_id)) == "backend_unavailable"


def test_module_refresh_rejects_an_empty_key_list(service: tuple[AnalysisService, str]) -> None:
    svc, session_id = service
    assert _err(svc.workflow_module_refresh(session_id, keys=[])) == "invalid_request"


def test_module_refresh_rejects_blank_or_duplicate_keys(
    service: tuple[AnalysisService, str],
) -> None:
    svc, session_id = service
    assert not svc.workflow_module_refresh(session_id, keys=["a", "a"]).ok
    assert not svc.workflow_module_refresh(session_id, keys=["  "]).ok


def test_breakpoint_put_rejects_a_blank_intent_id(service: tuple[AnalysisService, str]) -> None:
    svc, session_id = service
    result = svc.workflow_breakpoint_put(session_id, "", "payload", 0x1000)
    assert not result.ok and result.error is not None


def test_navigate_to_event_rejects_a_blank_kind(service: tuple[AnalysisService, str]) -> None:
    svc, session_id = service
    result = svc.workflow_navigate_to_event(session_id, "")
    assert not result.ok and result.error is not None


def test_navigate_to_breakpoint_rejects_an_out_of_range_budget(
    service: tuple[AnalysisService, str],
) -> None:
    svc, session_id = service
    result = svc.workflow_navigate_to_breakpoint(session_id, "oep", event_budget=0)
    assert _err(result) == "invalid_request"


# --- action bodies, run against a live (fake) paused session ----------------


def test_module_untrack_removes_a_tracked_module(tracked: tuple[AnalysisService, str]) -> None:
    svc, session_id = tracked
    result = svc.workflow_module_untrack(session_id, "payload")
    assert result.ok and result.data is not None
    assert result.data["module_key"] == "payload"


def test_module_refresh_runs_over_the_tracked_modules(tracked: tuple[AnalysisService, str]) -> None:
    svc, session_id = tracked
    result = svc.workflow_module_refresh(session_id)
    assert result.ok, result.error


def test_breakpoint_list_reports_the_current_intents(tracked: tuple[AnalysisService, str]) -> None:
    svc, session_id = tracked
    assert svc.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
    listed = svc.workflow_breakpoint_list(session_id)
    assert listed.ok and listed.data is not None
    assert listed.data["breakpoints"]["intents"][0]["id"] == "oep"


def test_navigate_to_an_undefined_breakpoint_intent_fails(
    tracked: tuple[AnalysisService, str],
) -> None:
    svc, session_id = tracked
    result = svc.workflow_navigate_to_breakpoint(session_id, "ghost", event_budget=8)
    assert not result.ok and result.error is not None


def test_navigate_to_a_disabled_breakpoint_intent_fails(
    tracked: tuple[AnalysisService, str],
) -> None:
    svc, session_id = tracked
    assert svc.workflow_breakpoint_put(session_id, "oep", "payload", 0x1234).ok
    assert svc.workflow_breakpoint_disable(session_id, "oep").ok
    result = svc.workflow_navigate_to_breakpoint(session_id, "oep", event_budget=8)
    assert not result.ok and result.error is not None
