"""Branch coverage for the _ui_drive burst state machine in service_ext.

The fail-closed cases live in test_ui_drive_terminate.py; this file drives the
input guards, the event-matching edge cases, the paused-resume barrier, and the
UI-step branches that only fire with particular window/step/event combinations.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_ext as ext
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service_ext import _ui_drive
from headless_re_mcp.core.windows import UiPidBoundaryError


class _Drive:
    """A service double exposing only what _ui_drive touches."""

    def __init__(self, tmp_path: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=tmp_path / "artifacts")
        self.settings.artifact_root.mkdir(parents=True, exist_ok=True)
        self.state_result: Any = Result(
            ok=True,
            data={"state": "running", "debuggee_pid": 4242, "debugger_pid": 100},
        )
        self.state_seq: list[Any] | None = None
        self.state_raises = False
        self.event_batches: list[Result[dict[str, Any]]] = []
        self.resume_result: Result[dict[str, Any]] = Result(ok=True, data={"state": "running"})
        self.wait_result: Result[dict[str, Any]] = Result(ok=True, data={"state": "running"})
        self.pause_raises = False
        self.paused = False

    def dynamic_state(self, session_id: str) -> Any:
        if self.state_raises:
            raise RuntimeError("state read blew up")
        if self.state_seq:
            return self.state_seq.pop(0)
        return self.state_result

    def dynamic_events(
        self, session_id: str, *, limit: int = 16, timeout: float = 0.2
    ) -> Result[dict[str, Any]]:
        if self.event_batches:
            return self.event_batches.pop(0)
        return Result(ok=True, data={"events": [], "count": 0})

    def dynamic_resume(self, session_id: str, timeout: float = 10.0) -> Result[dict[str, Any]]:
        return self.resume_result

    def dynamic_wait(
        self, session_id: str, target: str, timeout: float = 10.0
    ) -> Result[dict[str, Any]]:
        return self.wait_result

    def dynamic_pause(self, session_id: str, timeout: float = 10.0) -> Result[dict[str, Any]]:
        if self.pause_raises:
            raise RuntimeError("pause failed")
        self.paused = True
        return Result(ok=True, data={"state": "paused"})


def _run(service: _Drive, **over: Any) -> Result[dict[str, Any]]:
    params: dict[str, Any] = {
        "kind": "debug.paused",
        "fields": None,
        "steps": None,
        "timeout": 0.2,
        "event_budget": 32,
        "allow_child_pids": None,
        "accept_ui_goal": False,
        "breakpoint_intent_id": None,
    }
    params.update(over)
    return _ui_drive(service, "sess", **params)


def _patch_runtime(monkeypatch: pytest.MonkeyPatch, *, windows: Any = None) -> None:
    monkeypatch.setattr(ext, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        ext,
        "resolve_allowed_ui_pids",
        lambda **kwargs: (frozenset({4242}), []),
    )
    monkeypatch.setattr(ext, "list_windows_for_pids", lambda pids: list(windows or []))


def test_ui_drive_rejects_a_bad_timeout(tmp_path: Path) -> None:
    result = _run(_Drive(tmp_path), timeout=0.0)
    assert result.ok is False
    assert result.error is not None
    assert "timeout must be" in result.error.message


def test_ui_drive_rejects_a_bad_event_budget(tmp_path: Path) -> None:
    result = _run(_Drive(tmp_path), timeout=2.0, event_budget=0)
    assert result.ok is False
    assert result.error is not None
    assert "event_budget out of range" in result.error.message


def test_ui_drive_maps_a_pattern_build_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(kind: str, fields: Any) -> Any:
        raise ValueError("blank kind")

    monkeypatch.setattr(ext, "EventPattern", SimpleNamespace(create=_raise))
    result = _run(_Drive(tmp_path))
    assert result.ok is False
    assert result.error is not None
    assert "blank kind" in result.error.message


def test_ui_drive_maps_a_step_normalization_boundary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(steps: Any) -> Any:
        raise UiPidBoundaryError("invalid_params", "step escapes the pid boundary")

    monkeypatch.setattr(ext, "normalize_drive_steps", _raise)
    result = _run(_Drive(tmp_path), steps=[{"action": "click", "hwnd": 1}])
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_ui_drive_swallows_a_pause_failure_at_the_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.pause_raises = True
    result = _run(service, timeout=0.05)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_skips_noise_events_until_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.event_batches = [
        Result(
            ok=True,
            data={
                "events": [
                    "not-a-dict",
                    {"kind": "other", "data": {}},
                    {"kind": "goal.kind", "data": {"phase": "wrong"}},
                ],
            },
        )
    ]
    result = _run(
        service,
        kind="goal.kind",
        fields={"phase": "done"},
        timeout=0.05,
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_checks_every_field_before_rejecting_an_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first field matches so the loop advances to the second, which does
    # not -- exercising both the continue and the break inside the field check.
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.event_batches = [
        Result(
            ok=True,
            data={"events": [{"kind": "goal.kind", "data": {"a": 1, "b": 2}}]},
        )
    ]
    result = _run(
        service,
        kind="goal.kind",
        fields={"a": 1, "b": 999},
        timeout=0.05,
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_skips_a_breakpoint_hit_with_non_mapping_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.event_batches = [
        Result(ok=True, data={"events": [{"kind": "breakpoint.hit", "data": "nope"}]})
    ]
    result = _run(
        service,
        kind="breakpoint.hit",
        timeout=0.05,
        breakpoint_intent_id="t",
        breakpoint_address=0x401000,
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_tolerates_batches_without_a_usable_events_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.event_batches = [
        Result(ok=True, data={}),
        Result(ok=True, data={"events": "not-a-list"}),
    ]
    result = _run(service, timeout=0.05)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_fails_closed_when_state_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.state_result = Result(ok=False, error=RpcError(code="invalid_state", message="gone"))
    result = _run(service, timeout=1.0)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"
    assert service.paused is True


def test_ui_drive_fails_closed_without_a_debuggee_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.state_result = Result(ok=True, data={"state": "running"})
    result = _run(service, timeout=1.0)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_ui_drive_resumes_a_paused_debuggee_then_polls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    paused = Result(
        ok=True,
        data={"state": "paused", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    running = Result(
        ok=True,
        data={"state": "running", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    service.state_seq = [paused, running, running, running]
    result = _run(service, timeout=0.05)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_fails_closed_when_resume_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.state_result = Result(
        ok=True,
        data={"state": "paused", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    service.resume_result = Result(
        ok=False, error=RpcError(code="backend_error", message="resume refused")
    )
    result = _run(service, timeout=1.0)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_ui_drive_fails_closed_when_the_debuggee_will_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    paused = Result(
        ok=True,
        data={"state": "paused", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    stopped = Result(
        ok=True,
        data={"state": "stopped", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    service.state_seq = [paused, stopped, stopped]
    service.wait_result = Result(
        ok=False, error=RpcError(code="backend_error", message="never ran")
    )
    result = _run(service, timeout=1.0)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_ui_drive_tolerates_a_failed_wait_when_state_is_already_runnable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Resume returns ok, the "wait for running" probe fails, but a follow-up
    # state read shows the debuggee running -- so the drive proceeds instead of
    # failing closed.
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    paused = Result(
        ok=True,
        data={"state": "paused", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    running = Result(
        ok=True,
        data={"state": "running", "debuggee_pid": 4242, "debugger_pid": 100},
    )
    service.state_seq = [paused, running, running, running, running]
    service.wait_result = Result(
        ok=False, error=RpcError(code="backend_error", message="wait timed out")
    )
    result = _run(service, timeout=0.05)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_runs_a_step_even_before_any_window_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch, windows=[])
    monkeypatch.setattr(
        ext,
        "run_drive_step",
        lambda step, allowed_pids, handles: {
            "action": step.get("action"),
            "matched": False,
        },
    )
    service = _Drive(tmp_path)
    result = _run(
        service,
        steps=[{"action": "click", "hwnd": 1}, {"action": "click", "hwnd": 1}],
        timeout=0.05,
        accept_ui_goal=True,
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_maps_a_step_boundary_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(
        monkeypatch,
        windows=[{"hwnd": 1, "pid": 4242, "title": "A", "visible": True}],
    )

    def _raise(step: Any, *, allowed_pids: Any, handles: Any) -> Any:
        raise UiPidBoundaryError("permission_denied", "hwnd escapes pid boundary")

    monkeypatch.setattr(ext, "run_drive_step", _raise)
    service = _Drive(tmp_path)
    result = _run(
        service,
        steps=[{"action": "click", "hwnd": 1}],
        timeout=1.0,
        accept_ui_goal=True,
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "permission_denied"


def test_ui_drive_wait_match_without_accepting_the_ui_goal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(
        monkeypatch,
        windows=[{"hwnd": 1, "pid": 4242, "title": "A", "visible": True}],
    )
    monkeypatch.setattr(
        ext,
        "run_drive_step",
        lambda step, allowed_pids, handles: {"action": "wait", "matched": True},
    )
    service = _Drive(tmp_path)
    result = _run(
        service,
        steps=[{"action": "wait", "title_contains": "A", "timeout": 0.01}],
        timeout=0.05,
        accept_ui_goal=False,
    )
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_ui_drive_stops_on_a_non_incidental_event_between_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(
        monkeypatch,
        windows=[{"hwnd": 1, "pid": 4242, "title": "A", "visible": True}],
    )
    monkeypatch.setattr(
        ext,
        "run_drive_step",
        lambda step, allowed_pids, handles: {"action": "click", "matched": False},
    )
    service = _Drive(tmp_path)
    service.event_batches = [Result(ok=True, data={"events": [{"kind": "goal.kind", "data": {}}]})]
    result = _run(
        service,
        kind="goal.kind",
        steps=[{"action": "click", "hwnd": 1}],
        timeout=1.0,
        accept_ui_goal=True,
    )
    assert result.ok is True
    assert result.data is not None
    assert result.data["matched_event"] is not None


def test_ui_drive_maps_an_unexpected_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_runtime(monkeypatch)
    service = _Drive(tmp_path)
    service.state_raises = True
    result = _run(service, timeout=1.0)
    assert result.ok is False
    assert result.error is not None
    assert service.paused is True
