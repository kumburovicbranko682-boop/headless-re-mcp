"""Unit tests for M10.3 ui drive fail-closed termination."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.core.service_ext as service_ext_module
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _breakpoint_binding_address, _ui_drive
from headless_re_mcp.core.store import SessionStore


class _FakeService:
    def __init__(self, tmp_path: Path) -> None:
        self.settings = SimpleNamespace(
            artifact_root=tmp_path / "artifacts",
            persist_debug_events=False,
        )
        self.settings.artifact_root.mkdir(parents=True, exist_ok=True)
        self._store = SessionStore(self.settings.artifact_root / "meta" / "sessions.db")
        self._state = {
            "state": "running",
            "debuggee_pid": 4242,
            "debugger_pid": 100,
        }
        self._events: list[dict[str, object]] = []
        self.paused = False
        self.resume_calls = 0

    def dynamic_state(self, session_id: str) -> Result[dict[str, object]]:
        return Result(ok=True, data=dict(self._state))

    def dynamic_resume(self, session_id: str, timeout: float = 10.0) -> Result[dict[str, object]]:
        self.resume_calls += 1
        self._state["state"] = "running"
        return Result(ok=True, data={"state": "running"})

    def dynamic_pause(self, session_id: str, timeout: float = 10.0) -> Result[dict[str, object]]:
        self.paused = True
        self._state["state"] = "paused"
        return Result(ok=True, data={"state": "paused"})

    def dynamic_events(
        self, session_id: str, *, limit: int = 16, timeout: float = 0.2
    ) -> Result[dict[str, object]]:
        events = list(self._events)
        self._events.clear()
        return Result(ok=True, data={"events": events, "count": len(events)})


def test_ui_drive_target_exited_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeService(tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: False,
    )
    result = _ui_drive(
        service,
        "sess",
        kind="debug.paused",
        fields=None,
        steps=None,
        timeout=2.0,
        event_budget=8,
        allow_child_pids=None,
        accept_ui_goal=True,
        breakpoint_intent_id=None,
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "target_exited"
    assert service.paused is True


def test_ui_drive_window_gone_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeService(tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: True,
    )
    calls = {"n": 0}

    def _windows(_pids: object) -> list[dict[str, object]]:
        calls["n"] += 1
        if calls["n"] == 1:
            return [{"hwnd": 1, "pid": 4242, "title": "A", "class_name": "X", "visible": True}]
        return []

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.list_windows_for_pids",
        _windows,
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.run_drive_step",
        lambda step, allowed_pids, handles: {"action": step.get("action"), "matched": False},
    )
    result = _ui_drive(
        service,
        "sess",
        kind="debug.paused",
        fields=None,
        steps=[
            {"action": "wait", "title_contains": "never", "timeout": 0.05},
            {"action": "wait", "title_contains": "never", "timeout": 0.05},
        ],
        timeout=2.0,
        event_budget=8,
        allow_child_pids=None,
        accept_ui_goal=True,
        breakpoint_intent_id=None,
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "window_gone"
    assert service.paused is True


def test_ui_drive_burst_peeks_events_between_steps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Between UI steps, event wait must stay short (burst architecture)."""
    service = _FakeService(tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: True,
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.list_windows_for_pids",
        lambda _pids: [{"hwnd": 1, "pid": 4242, "title": "A", "class_name": "X", "visible": True}],
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.run_drive_step",
        lambda step, allowed_pids, handles: {
            "action": step.get("action"),
            "matched": step.get("action") == "wait",
        },
    )
    peeked: list[float] = []

    def _events(
        session_id: str,
        *,
        limit: int = 16,
        timeout: float = 0.2,
    ) -> Result[dict[str, object]]:
        peeked.append(float(timeout))
        return Result(ok=True, data={"events": [], "count": 0})

    service.dynamic_events = _events  # type: ignore[method-assign]
    result = _ui_drive(
        service,
        "sess",
        kind="debug.paused",
        fields=None,
        steps=[
            {"action": "click", "hwnd": 1},
            {"action": "click", "hwnd": 1},
            {"action": "wait", "title_contains": "A", "timeout": 0.01},
        ],
        timeout=5.0,
        event_budget=32,
        allow_child_pids=None,
        accept_ui_goal=True,
        breakpoint_intent_id=None,
    )
    assert result.ok and result.data is not None
    assert result.data.get("architecture") == "ui_burst"
    assert peeked, "expected event peeks between steps"
    assert all(t <= 0.1 for t in peeked), peeked


def test_ui_drive_event_loss_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeService(tmp_path)
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: True,
    )

    def _events(
        session_id: str,
        *,
        limit: int = 16,
        timeout: float = 0.2,
    ) -> Result[dict[str, object]]:
        return Result(ok=False, error=RpcError(code="invalid_state", message="cursor lost"))

    service.dynamic_events = _events  # type: ignore[method-assign]
    result = _ui_drive(
        service,
        "sess",
        kind="debug.paused",
        fields=None,
        steps=None,
        timeout=1.0,
        event_budget=4,
        allow_child_pids=None,
        accept_ui_goal=False,
        breakpoint_intent_id=None,
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "event_loss"
    assert service.paused is True


def test_ui_drive_terminal_event_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeService(tmp_path)
    service._events = [{"kind": "process.exited", "data": {"exit_code": 1}}]
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: True,
    )
    result = _ui_drive(
        service,
        "sess",
        kind="debug.paused",
        fields=None,
        steps=None,
        timeout=2.0,
        event_budget=8,
        allow_child_pids=None,
        accept_ui_goal=False,
        breakpoint_intent_id=None,
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "target_exited"
    assert service.paused is True


def test_breakpoint_binding_address_requires_one_active_binding() -> None:
    workflow = {
        "workflow": {
            "state": {
                "breakpoints": {
                    "bindings": [
                        {"intent_id": "transform", "address": 0x401000},
                    ]
                }
            }
        }
    }

    assert _breakpoint_binding_address(workflow, "transform") == 0x401000
    with pytest.raises(XdbgRpcError) as exc_info:
        _breakpoint_binding_address(workflow, "missing")
    assert exc_info.value.code == "invalid_state"


def test_ui_drive_to_breakpoint_resolves_current_binding_before_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = object.__new__(AnalysisService)
    workflow: Result[dict[str, object]] = Result(
        ok=True,
        data={
            "workflow": {
                "state": {
                    "breakpoints": {
                        "bindings": [
                            {"intent_id": "transform", "address": 0x401000},
                        ]
                    }
                }
            }
        },
    )
    monkeypatch.setattr(service, "workflow_status", lambda session_id: workflow)
    captured: dict[str, object] = {}

    def _drive(*args: object, **kwargs: object) -> Result[dict[str, object]]:
        captured.update(kwargs)
        return Result(ok=True, data={"matched_event": None})

    monkeypatch.setattr(service_ext_module, "_ui_drive", _drive)

    result = service.ui_drive_to_breakpoint("sess", "transform")

    assert result.ok is True
    assert captured["breakpoint_intent_id"] == "transform"
    assert captured["breakpoint_address"] == 0x401000
    assert captured["fields"] == {"intent_id": "transform", "address": 0x401000}


def test_ui_drive_breakpoint_copies_and_annotates_native_hit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeService(tmp_path)
    source_event = {
        "sequence": 7,
        "kind": "breakpoint.hit",
        "data": {"address": 0x401000, "type": 0},
    }
    service._events = [source_event]
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: True,
    )

    result = _ui_drive(
        service,
        "sess",
        kind="breakpoint.hit",
        fields={"intent_id": "transform", "address": 0x401000},
        steps=None,
        timeout=1.0,
        event_budget=8,
        allow_child_pids=None,
        accept_ui_goal=False,
        breakpoint_intent_id="transform",
        breakpoint_address=0x401000,
    )

    assert result.ok is True
    assert result.data is not None
    matched = result.data["matched_event"]
    assert isinstance(matched, dict)
    assert matched["data"] == {
        "address": 0x401000,
        "type": 0,
        "intent_id": "transform",
        "binding_address": 0x401000,
    }
    assert source_event["data"] == {"address": 0x401000, "type": 0}


def test_ui_drive_breakpoint_rejects_wrong_intent_and_address_until_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeService(tmp_path)
    service._events = [
        {
            "sequence": 8,
            "kind": "breakpoint.hit",
            "data": {"address": 0x402000},
        },
        {
            "sequence": 9,
            "kind": "breakpoint.hit",
            "data": {"address": 0x401000, "intent_id": "other"},
        },
    ]
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.is_pid_alive",
        lambda pid: True,
    )

    result = _ui_drive(
        service,
        "sess",
        kind="breakpoint.hit",
        fields={"intent_id": "transform", "address": 0x401000},
        steps=None,
        timeout=0.02,
        event_budget=8,
        allow_child_pids=None,
        accept_ui_goal=False,
        breakpoint_intent_id="transform",
        breakpoint_address=0x401000,
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert service.paused is True
