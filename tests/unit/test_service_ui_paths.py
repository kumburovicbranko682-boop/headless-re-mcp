"""Unit coverage for the PID-bounded UI automation service mixin.

Every entry point is Windows-gated. These tests fake ``os.name`` as ``"nt"``
and stub the Win32/UIA helper layer so the service-level surface -- envelope
shaping, the resume-before-interact dance, and the PID-boundary error mapping
-- can be exercised on Linux without a real debuggee.
"""

from __future__ import annotations

import os
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import headless_re_mcp.core.process_tree as process_tree
import headless_re_mcp.core.service_ui as svc_ui
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service_ui import (
    UiAutomationMixin,
    _annotate_virtual_desktop_snapshot,
    _as_positive_pid,
    _desktop_monitor_pids,
    _select_desktop_window,
    _ui_backend_key,
    _ui_finalize_windows,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_RUNNING = {"debuggee_pid": 1234, "debugger_pid": 1000, "state": "running"}
_PAUSED = {"debuggee_pid": 1234, "debugger_pid": 1000, "state": "paused"}

# Loaded once while os.name is still posix: Settings.load() resolves a
# user_config_path, which mints a WindowsPath (uninstantiable on Linux) once a
# test fakes os.name as "nt". replace() below never re-reads the platform.
_BASE_SETTINGS = Settings.load()


class _FakeWorker:
    def __init__(
        self,
        *,
        capabilities: set[str],
        state: dict[str, Any],
        pid: int = 1000,
        wait_state: dict[str, Any] | None = None,
        wait_error: BaseException | None = None,
        desktop_snapshot: Any = None,
        desktop_capture: Any = None,
    ) -> None:
        self.capabilities = set(capabilities)
        self._state = state
        self.pid = pid
        self._wait_state = wait_state
        self._wait_error = wait_error
        self.calls: list[str] = []
        if desktop_snapshot is not None:
            self.desktop_snapshot = desktop_snapshot
        if desktop_capture is not None:
            self.desktop_capture = desktop_capture

    def request(
        self, method: str, params: Any = None, *, timeout: float | None = None
    ) -> dict[str, Any]:
        self.calls.append(method)
        if method == "debug.state":
            return dict(self._state)
        return {}

    def wait_for_state(self, states: set[str], *, timeout: float) -> dict[str, Any]:
        if self._wait_error is not None:
            raise self._wait_error
        return dict(self._wait_state or self._state)


class _FakeUiService(UiAutomationMixin):
    _runtime_obj: Any

    def __init__(
        self,
        worker: _FakeWorker,
        *,
        artifact_root: Path,
        hidden_desktop: bool = False,
        windows_list_result: Any = None,
    ) -> None:
        self.settings = replace(
            _BASE_SETTINGS, artifact_root=artifact_root, hidden_desktop=hidden_desktop
        )
        self.services = cast(
            Any,
            SimpleNamespace(
                interaction=SimpleNamespace(
                    windows_list=lambda session_id, **kw: windows_list_result
                )
            ),
        )
        self._runtime_obj = SimpleNamespace(worker=worker, lock=threading.Lock())
        self.failed: list[tuple[BackendKind, BaseException | None]] = []
        self.observed: list[dict[str, Any]] = []

    def _runtime(self, session_id: str, kind: BackendKind) -> Any:
        return self._runtime_obj

    def _require_current_runtime(self, session_id: str, kind: BackendKind, runtime: Any) -> None:
        return None

    def _fail_runtime(
        self,
        session_id: str,
        kind: BackendKind,
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.failed.append((kind, failure))

    def _observe_debuggee_state(self, session_id: str, state: dict[str, Any]) -> dict[str, Any]:
        self.observed.append(state)
        return state

    def _annotate_debuggee_pids(self, session_id: str, state: dict[str, Any]) -> dict[str, Any]:
        return dict(state)


class _NtOsProxy:
    """Report ``name == "nt"`` while forwarding everything else to the real os.

    Patching the global ``os.name`` would poison ``pathlib.Path`` on Python 3.11,
    where ``Path()`` picks WindowsPath (uninstantiable on POSIX) from ``os.name``.
    """

    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


@pytest.fixture
def _nt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc_ui, "os", _NtOsProxy())


def _install_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc_ui,
        "resolve_allowed_ui_pids",
        lambda *, debuggee_pid, debugger_pid, allow_child_pids, include_same_image_children: (
            frozenset({debuggee_pid}),
            frozenset({debugger_pid} if debugger_pid else set()),
        ),
    )


# --------------------------------------------------------------------------
# _as_positive_pid
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (42, 42),
        (0, None),
        (-5, None),
        ("17", 17),
        ("0", None),
        ("abc", None),
        (None, None),
        (True, None),
    ],
)
def test_as_positive_pid(value: object, expected: int | None) -> None:
    assert _as_positive_pid(value) == expected


# --------------------------------------------------------------------------
# _desktop_monitor_pids
# --------------------------------------------------------------------------


def test_desktop_monitor_pids_returns_empty_without_a_live_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)
    assert _desktop_monitor_pids({}) == (frozenset(), None)

    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: False)
    assert _desktop_monitor_pids({"process_id": 5}) == (frozenset(), None)


def test_desktop_monitor_pids_adds_live_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: pid != 99)
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid: [77, 99])
    allowed, target = _desktop_monitor_pids({"debuggee_pid": 5})
    assert target == 5
    assert allowed == frozenset({5, 77})


# --------------------------------------------------------------------------
# _annotate_virtual_desktop_snapshot
# --------------------------------------------------------------------------


def _annotate(state: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    return _annotate_virtual_desktop_snapshot(
        snapshot,
        session_id="s",
        state=state,
        allowed=frozenset({5}),
        debuggee_pid=5,
        debugger_pid=1,
    )


def test_annotate_snapshot_paused_hint() -> None:
    payload = _annotate({"state": "paused"}, {"windows": "bogus"})
    assert payload["window_count"] == 0
    assert payload["desktop_window_count"] == 0
    assert payload["hint"] == "paused_before_gui"
    assert "dynamic.resume" in payload["suggestion"]


def test_annotate_snapshot_running_hint() -> None:
    payload = _annotate({"state": "running"}, {})
    assert payload["hint"] == "no_debuggee_windows"


def test_annotate_snapshot_idle_hint_defaults_state() -> None:
    payload = _annotate({}, {})
    assert payload["debuggee_state"] == "idle"
    assert payload["hint"] == "debuggee_idle"


def test_annotate_snapshot_keeps_existing_hint_and_counts() -> None:
    payload = _annotate(
        {"state": "paused"},
        {"windows": [{"hwnd": 1}], "desktop_window_count": 9, "hint": "custom"},
    )
    assert payload["window_count"] == 1
    assert payload["desktop_window_count"] == 9
    assert payload["hint"] == "custom"


# --------------------------------------------------------------------------
# _select_desktop_window
# --------------------------------------------------------------------------


def test_select_desktop_window_requires_a_positive_hwnd() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _select_desktop_window([], requested_hwnd=0)


def test_select_desktop_window_finds_the_requested_hwnd() -> None:
    row = {"hwnd": 7}
    assert _select_desktop_window([{"hwnd": 3}, row], requested_hwnd=7) is row


def test_select_desktop_window_rejects_an_unauthorized_hwnd() -> None:
    with pytest.raises(XdbgRpcError) as info:
        _select_desktop_window([{"hwnd": 3}], requested_hwnd=7)
    assert info.value.code == "not_found"


def test_select_desktop_window_needs_at_least_one_window() -> None:
    with pytest.raises(XdbgRpcError) as info:
        _select_desktop_window([], requested_hwnd=None)
    assert info.value.code == "not_found"


def test_select_desktop_window_ranks_by_capture_weight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc_ui, "window_capture_rank", lambda row: row["score"])
    best = {"hwnd": 2, "score": 9}
    assert _select_desktop_window([{"hwnd": 1, "score": 3}, best], requested_hwnd=None) is best


# --------------------------------------------------------------------------
# _ui_finalize_windows
# --------------------------------------------------------------------------


def test_finalize_windows_rejects_a_pid_outside_the_allow_set() -> None:
    with pytest.raises(UiPidBoundaryError) as info:
        _ui_finalize_windows(
            {"windows": [{"hwnd": 1, "pid": 999}]},
            {"allowed": frozenset({7}), "debuggee_pid": 7},
        )
    assert info.value.code == "permission_denied"


def test_finalize_windows_counts_and_skips_non_dict_rows() -> None:
    payload = _ui_finalize_windows(
        {"windows": ["noise", {"hwnd": 1, "pid": 7}]},
        {"allowed": frozenset({7}), "debuggee_pid": 7},
    )
    assert payload["count"] == 2


def test_finalize_windows_suggests_child_pids_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        process_tree,
        "probe_child_window_candidates",
        lambda pid, list_windows_fn=None: [{"pid": 55}],
    )
    payload = _ui_finalize_windows({"windows": []}, {"allowed": frozenset({7}), "debuggee_pid": 7})
    assert payload["hint"] == "windows_on_child_pids"
    assert payload["suggested_child_pids"] == [55]


def test_finalize_windows_tolerates_a_failing_child_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)

    def boom(pid: int, list_windows_fn: Any = None) -> Any:
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(process_tree, "probe_child_window_candidates", boom)
    payload = _ui_finalize_windows({"windows": []}, {"allowed": frozenset({7}), "debuggee_pid": 7})
    assert "child_candidates" not in payload


def test_finalize_windows_hidden_desktop_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: False)
    payload = _ui_finalize_windows(
        {"windows": []},
        {"allowed": frozenset({7}), "debuggee_pid": 7},
        hidden_desktop=True,
    )
    assert payload["hint"] == "windows_on_hidden_desktop"


def test_finalize_windows_non_list_becomes_empty() -> None:
    payload = _ui_finalize_windows(
        {"windows": None}, {"allowed": frozenset({7}), "debuggee_pid": 0}
    )
    assert payload["windows"] == []
    assert payload["count"] == 0


# --------------------------------------------------------------------------
# virtual_desktop_snapshot / capture
# --------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_snapshot_is_unsupported_off_windows(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.virtual_desktop_snapshot("s")
    assert result.error is not None
    assert result.error.code == "unsupported_on_platform"


def test_snapshot_requires_worker_desktop_capability(tmp_path: Path, _nt: None) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.virtual_desktop_snapshot("s")
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_snapshot_refuses_a_non_object_payload(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: False)
    worker = _FakeWorker(
        capabilities={"debug.state"},
        state=_RUNNING,
        desktop_snapshot=lambda *, allowed_pids: ["not", "a", "dict"],
    )
    service = _FakeUiService(worker, artifact_root=tmp_path)
    result = service.virtual_desktop_snapshot("s")
    assert result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_snapshot_annotates_a_clean_result(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid: [])
    worker = _FakeWorker(
        capabilities={"debug.state"},
        state={"debuggee_pid": 1234, "state": "running"},
        desktop_snapshot=lambda *, allowed_pids: {"windows": [{"hwnd": 1}]},
    )
    service = _FakeUiService(worker, artifact_root=tmp_path)
    result = service.virtual_desktop_snapshot("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["debuggee_pid"] == 1234
    assert result.data["capture_mode"] == "passive"


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_capture_is_unsupported_off_windows(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.virtual_desktop_capture("s")
    assert result.error is not None
    assert result.error.code == "unsupported_on_platform"


def test_capture_requires_both_desktop_functions(tmp_path: Path, _nt: None) -> None:
    worker = _FakeWorker(
        capabilities={"debug.state"},
        state=_RUNNING,
        desktop_snapshot=lambda *, allowed_pids: {"windows": []},
    )
    service = _FakeUiService(worker, artifact_root=tmp_path)
    result = service.virtual_desktop_capture("s")
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_capture_refuses_a_non_object_payload(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid: [])
    worker = _FakeWorker(
        capabilities={"debug.state"},
        state=_RUNNING,
        desktop_snapshot=lambda *, allowed_pids: {"windows": [{"hwnd": 7}]},
        desktop_capture=lambda hwnd, *, allowed_pids, output_path: "not a dict",
    )
    service = _FakeUiService(worker, artifact_root=tmp_path)
    result = service.virtual_desktop_capture("s", hwnd=7)
    assert result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_capture_images_the_selected_window(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid: [])
    captured: dict[str, Any] = {}

    def capture(hwnd: int, *, allowed_pids: Any, output_path: Path) -> dict[str, Any]:
        captured["hwnd"] = hwnd
        captured["path"] = output_path
        return {"bytes": 4}

    worker = _FakeWorker(
        capabilities={"debug.state"},
        state=_RUNNING,
        desktop_snapshot=lambda *, allowed_pids: {"windows": [{"hwnd": 7}]},
        desktop_capture=capture,
    )
    service = _FakeUiService(worker, artifact_root=tmp_path)
    result = service.virtual_desktop_capture("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["intrusion"] == "on_demand_printwindow"
    assert captured["hwnd"] == 7
    assert str(captured["path"]).endswith("window-7.bmp")


# --------------------------------------------------------------------------
# ui_windows_list delegation
# --------------------------------------------------------------------------


def test_ui_windows_list_delegates_to_interaction(tmp_path: Path) -> None:
    marker: Any = SimpleNamespace(ok=True)
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
        windows_list_result=marker,
    )
    assert cast(Any, service.ui_windows_list("s")) is marker


# --------------------------------------------------------------------------
# _ui_call orchestration through concrete endpoints
# --------------------------------------------------------------------------


def _service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: dict[str, Any],
    capabilities: set[str] | None = None,
    wait_state: dict[str, Any] | None = None,
    wait_error: BaseException | None = None,
) -> _FakeUiService:
    _install_helpers(monkeypatch)
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)
    worker = _FakeWorker(
        capabilities=(
            capabilities if capabilities is not None else {"debug.state", "debug.resume"}
        ),
        state=state,
        wait_state=wait_state,
        wait_error=wait_error,
    )
    return _FakeUiService(worker, artifact_root=tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_ui_call_is_unsupported_off_windows(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.ui_resolve("s", hwnd=1)
    assert result.error is not None
    assert result.error.code == "unsupported_on_platform"


def test_ui_call_requires_debug_state_capability(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, monkeypatch, state=_RUNNING, capabilities=set())
    result = service.ui_resolve("s", hwnd=1)
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_ui_call_refuses_without_a_live_debuggee(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(
        tmp_path,
        monkeypatch,
        state={"debuggee_pid": 0, "debugger_pid": 1000, "state": "running"},
    )
    result = service.ui_resolve("s", hwnd=1)
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_ui_resolve_returns_the_matched_window(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "resolve_hwnd", lambda allowed, **kw: {"hwnd": 5, "title": "t"})
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_resolve("s", hwnd=5)
    assert result.ok is True
    assert result.data is not None
    assert result.data["window"] == {"hwnd": 5, "title": "t"}
    assert result.data["debuggee_pid"] == 1234


def test_ui_resolve_maps_a_pid_boundary_violation_from_the_action(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(allowed: Any, **kw: Any) -> Any:
        raise UiPidBoundaryError("permission_denied", "escaped", pid=42)

    monkeypatch.setattr(svc_ui, "resolve_hwnd", boom)
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_resolve("s", hwnd=5)
    assert result.error is not None
    assert result.error.code == "permission_denied"
    assert result.error.details["debuggee_pid"] == 1234


def test_ui_call_maps_a_boundary_error_from_pid_resolution(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "is_pid_alive", lambda pid: True)

    def refuse(**kw: Any) -> Any:
        raise UiPidBoundaryError("permission_denied", "blocked pid", pid=1000)

    monkeypatch.setattr(svc_ui, "resolve_allowed_ui_pids", refuse)
    worker = _FakeWorker(capabilities={"debug.state"}, state=_RUNNING)
    service = _FakeUiService(worker, artifact_root=tmp_path)
    result = service.ui_resolve("s", hwnd=1)
    assert result.error is not None
    assert result.error.code == "permission_denied"


def test_ui_call_resumes_a_paused_debuggee_before_interacting(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        svc_ui, "click_hwnd", lambda hwnd, allowed, *, timeout_ms: {"action": "click"}
    )
    service = _service(tmp_path, monkeypatch, state=_PAUSED, wait_state=_RUNNING)
    result = service.ui_click("s", 5)
    assert result.ok is True
    assert "debug.resume" in service._runtime_obj.worker.calls


def test_ui_call_reports_a_resume_that_fails_hard(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(
        tmp_path,
        monkeypatch,
        state=_PAUSED,
        wait_error=XdbgRpcError("rpc_transport_error", "gone"),
    )
    result = service.ui_click("s", 5)
    assert result.error is not None
    assert result.error.code == "resume_failed"


def test_ui_call_tolerates_a_resume_timeout_and_continues(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        svc_ui, "click_hwnd", lambda hwnd, allowed, *, timeout_ms: {"action": "click"}
    )
    service = _service(
        tmp_path,
        monkeypatch,
        state=_PAUSED,
        wait_error=XdbgRpcError("timeout", "still paused"),
    )
    result = service.ui_click("s", 5)
    assert result.ok is True
    assert service._runtime_obj.worker.calls.count("debug.state") == 2


def test_ui_call_files_a_fatal_worker_error_against_the_runtime(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(allowed: Any, **kw: Any) -> Any:
        raise XdbgRpcError("worker_exited", "worker died")

    monkeypatch.setattr(svc_ui, "resolve_hwnd", boom)
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_resolve("s", hwnd=1)
    assert result.error is not None
    assert result.error.code == "worker_exited"
    assert service.failed and service.failed[0][0] is BackendKind.X64DBG


def test_ui_call_reports_an_unexpected_exception(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(allowed: Any, **kw: Any) -> Any:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(svc_ui, "resolve_hwnd", boom)
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_resolve("s", hwnd=1)
    assert result.error is not None
    assert result.error.code == "internal_error"
    assert not service.failed


# --------------------------------------------------------------------------
# per-endpoint actions
# --------------------------------------------------------------------------


def test_ui_windows_list_action_finalizes(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "list_windows_for_pids", lambda pids: [{"hwnd": 1, "pid": 1234}])
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service._ui_windows_list("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["count"] == 1


def test_ui_process_tree_probes_children_without_resuming(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process_tree, "enumerate_direct_children", lambda pid: [55])
    monkeypatch.setattr(process_tree, "process_image_path", lambda pid: f"/img/{pid}")
    monkeypatch.setattr(
        process_tree,
        "probe_child_window_candidates",
        lambda pid, list_windows_fn=None: [],
    )
    monkeypatch.setattr(svc_ui, "list_windows_for_pids", lambda pids: [])
    service = _service(tmp_path, monkeypatch, state=_PAUSED)
    result = service.ui_process_tree("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["children"][0]["pid"] == 55
    assert "debug.resume" not in service._runtime_obj.worker.calls


def test_ui_tree_uia_requires_a_root(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_tree("s", backend="uia")
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_ui_tree_uia_builds_the_tree(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "build_uia_tree", lambda root, allowed, **kw: {"nodes": 2})
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_tree("s", backend="uia", root_hwnd=9)
    assert result.ok is True
    assert result.data is not None
    assert result.data["nodes"] == 2


def test_ui_tree_win32_from_a_root_hwnd(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "resolve_hwnd", lambda allowed, **kw: {"hwnd": 9})
    monkeypatch.setattr(svc_ui, "build_window_tree", lambda roots, allowed, **kw: {"nodes": 1})
    monkeypatch.setattr(svc_ui, "uia_available", lambda: False)
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_tree("s", root_hwnd=9)
    assert result.ok is True
    assert result.data is not None
    assert result.data["backend"] == "win32_enum"


def test_ui_tree_win32_enumerates_when_no_root(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "list_windows_for_pids", lambda pids: [{"hwnd": 1}])
    monkeypatch.setattr(svc_ui, "build_window_tree", lambda roots, allowed, **kw: {"nodes": 3})
    monkeypatch.setattr(svc_ui, "uia_available", lambda: True)
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_tree("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["uia_available"] is True


@pytest.mark.parametrize("backend", ["uia", "sendinput", "win32"])
def test_ui_click_backends(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    monkeypatch.setattr(svc_ui, "click_hwnd_uia", lambda hwnd, allowed: {"via": "uia"})
    monkeypatch.setattr(svc_ui, "click_hwnd_sendinput", lambda hwnd, allowed: {"via": "sendinput"})
    monkeypatch.setattr(svc_ui, "click_hwnd", lambda hwnd, allowed, *, timeout_ms: {"via": "win32"})
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_click("s", 5, backend=backend)
    assert result.ok is True
    assert result.data is not None
    expected = backend if backend != "win32" else "win32"
    assert result.data["via"] == expected


def test_ui_click_at_posts_the_click(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        svc_ui,
        "click_hwnd_at",
        lambda hwnd, allowed, *, x, y, timeout_ms: {"x": x, "y": y},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_click_at("s", 5, 3, 4)
    assert result.ok is True
    assert result.data is not None
    assert result.data["x"] == 3


def test_ui_window_close_forwards_the_method(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        svc_ui,
        "close_hwnd",
        lambda hwnd, allowed, *, method, timeout_ms: {"method": method},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_window_close("s", 5, method="wm_close")
    assert result.ok is True
    assert result.data is not None
    assert result.data["method"] == "wm_close"


@pytest.mark.parametrize("backend", ["uia", "win32"])
def test_ui_text_set_backends(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    monkeypatch.setattr(svc_ui, "set_value_uia", lambda hwnd, text, allowed: {"via": "uia"})
    monkeypatch.setattr(
        svc_ui,
        "set_window_text",
        lambda hwnd, text, allowed, *, timeout_ms: {"via": "win32"},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_text_set("s", 5, "hi", backend=backend)
    assert result.ok is True
    assert result.data is not None
    assert result.data["via"] == backend


@pytest.mark.parametrize("backend", ["sendinput", "win32"])
def test_ui_key_backends(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    monkeypatch.setattr(
        svc_ui,
        "send_key_sendinput",
        lambda hwnd, *, allowed_pids, text, vk: {"via": "sendinput"},
    )
    monkeypatch.setattr(
        svc_ui,
        "send_key",
        lambda hwnd, *, allowed_pids, text, vk, timeout_ms: {"via": "win32"},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_key("s", 5, text="a", backend=backend)
    assert result.ok is True
    assert result.data is not None
    assert result.data["via"] == backend


# --------------------------------------------------------------------------
# _ui_backend_key
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "win32"),
        ("", "win32"),
        ("   ", "win32"),
        ("win32", "win32"),
        ("  UIA  ", "uia"),
        ("UiAutomation", "uiautomation"),
        ("INPUT", "input"),
        ("sendinput", "sendinput"),
        # An unknown selector is preserved (the caller routes it to its default).
        ("mystery", "mystery"),
    ],
)
def test_ui_backend_key_normalizes_strings(value: object, expected: str) -> None:
    assert _ui_backend_key(value) == expected


@pytest.mark.parametrize("bad", [5, 1.5, [1], {"a": 1}, (1,), b"win32", True, False])
def test_ui_backend_key_rejects_non_strings(bad: object) -> None:
    # The old ``(backend or "win32").strip()`` crashed .strip() with an
    # AttributeError on a truthy non-string; reject it as invalid_params here.
    with pytest.raises(UiPidBoundaryError) as excinfo:
        _ui_backend_key(bad)
    assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad_backend", [5, 1.5, [1], {"a": 1}, b"win32", True])
def test_ui_click_refuses_a_non_string_backend(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, bad_backend: object
) -> None:
    dispatched: list[str] = []
    monkeypatch.setattr(
        svc_ui, "click_hwnd_uia", lambda hwnd, allowed: dispatched.append("uia") or {}
    )
    monkeypatch.setattr(
        svc_ui,
        "click_hwnd_sendinput",
        lambda hwnd, allowed: dispatched.append("sendinput") or {},
    )
    monkeypatch.setattr(
        svc_ui,
        "click_hwnd",
        lambda hwnd, allowed, *, timeout_ms: dispatched.append("win32") or {},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_click("s", 5, backend=cast(Any, bad_backend))
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert dispatched == []


@pytest.mark.parametrize("bad_backend", [5, 1.5, [1], {"a": 1}, b"win32", True])
def test_ui_tree_refuses_a_non_string_backend(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, bad_backend: object
) -> None:
    dispatched: list[str] = []
    monkeypatch.setattr(
        svc_ui, "build_uia_tree", lambda root, allowed, **kw: dispatched.append("uia") or {}
    )
    monkeypatch.setattr(
        svc_ui,
        "build_window_tree",
        lambda roots, allowed, **kw: dispatched.append("win32") or {},
    )
    monkeypatch.setattr(svc_ui, "list_windows_for_pids", lambda pids: [])
    monkeypatch.setattr(svc_ui, "uia_available", lambda: False)
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_tree("s", backend=cast(Any, bad_backend))
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert dispatched == []


@pytest.mark.parametrize("bad_backend", [5, 1.5, [1], {"a": 1}, b"win32", True])
def test_ui_text_set_refuses_a_non_string_backend(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, bad_backend: object
) -> None:
    dispatched: list[str] = []
    monkeypatch.setattr(
        svc_ui, "set_value_uia", lambda hwnd, text, allowed: dispatched.append("uia") or {}
    )
    monkeypatch.setattr(
        svc_ui,
        "set_window_text",
        lambda hwnd, text, allowed, *, timeout_ms: dispatched.append("win32") or {},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_text_set("s", 5, "hi", backend=cast(Any, bad_backend))
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert dispatched == []


@pytest.mark.parametrize("bad_backend", [5, 1.5, [1], {"a": 1}, b"win32", True])
def test_ui_key_refuses_a_non_string_backend(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch, bad_backend: object
) -> None:
    dispatched: list[str] = []
    monkeypatch.setattr(
        svc_ui,
        "send_key_sendinput",
        lambda hwnd, *, allowed_pids, text, vk: dispatched.append("sendinput") or {},
    )
    monkeypatch.setattr(
        svc_ui,
        "send_key",
        lambda hwnd, *, allowed_pids, text, vk, timeout_ms: dispatched.append("win32") or {},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_key("s", 5, text="a", backend=cast(Any, bad_backend))
    assert result.error is not None
    assert result.error.code == "invalid_params"
    assert dispatched == []


def test_ui_invoke_forwards_the_action(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        svc_ui,
        "invoke_hwnd",
        lambda hwnd, allowed, *, action, text, control_id, timeout_ms: {"action": action},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_invoke("s", 5, action_name="toggle")
    assert result.ok is True
    assert result.data is not None
    assert result.data["action"] == "toggle"


def test_ui_wait_polls_for_a_window(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc_ui, "wait_for_window", lambda allowed, **kw: {"matched": True})
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_wait("s", title="dlg")
    assert result.ok is True
    assert result.data is not None
    assert result.data["backend"] == "win32_poll"


# --------------------------------------------------------------------------
# _register_ui_capture / ui_screenshot / ui_ocr
# --------------------------------------------------------------------------


def test_register_ui_capture_is_a_noop_on_failure(tmp_path: Path) -> None:
    from headless_re_mcp.core.models import Result, RpcError

    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    failed: Result[dict[str, Any]] = Result(ok=False, error=RpcError(code="x", message="y"))
    assert (
        service._register_ui_capture(failed, "s", tmp_path / "f.bmp", kind="k", source="src")
        is failed
    )


def test_register_ui_capture_skips_a_missing_file(tmp_path: Path) -> None:
    from headless_re_mcp.core.models import Result

    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    ok: Result[dict[str, Any]] = Result(ok=True, data={"a": 1})
    assert (
        service._register_ui_capture(ok, "s", tmp_path / "missing.bmp", kind="k", source="src")
        is ok
    )


def test_register_ui_capture_updates_a_present_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.core.models import Result

    monkeypatch.setattr(
        svc_ui,
        "_register_capture",
        lambda self, session_id, path, *, kind, source, payload: {"artifact": "x"},
    )
    present = tmp_path / "shot.bmp"
    present.write_bytes(b"BM")
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    ok: Result[dict[str, Any]] = Result(ok=True, data={"a": 1})
    updated = service._register_ui_capture(ok, "s", present, kind="k", source="src")
    assert updated.data is not None
    assert updated.data["artifact"] == "x"


def test_ui_screenshot_rejects_a_path_escaping_session(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.ui_screenshot("..", 5)
    assert result.error is not None
    assert result.error.code == "invalid_request"


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_ui_screenshot_is_unsupported_off_windows(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.ui_screenshot("s", 5)
    assert result.error is not None
    assert result.error.code == "unsupported_on_platform"


def test_ui_screenshot_captures_and_registers(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def capture(hwnd: int, allowed: Any, path: Path, *, client_only: bool) -> dict[str, Any]:
        path.write_bytes(b"BM")
        return {"bytes": 2}

    monkeypatch.setattr(svc_ui, "capture_hwnd_screenshot", capture)
    monkeypatch.setattr(
        svc_ui,
        "_register_capture",
        lambda self, session_id, path, *, kind, source, payload: {"artifact_id": "a"},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_screenshot("s", 5)
    assert result.ok is True
    assert result.data is not None
    assert result.data["artifact_id"] == "a"


def test_ui_ocr_rejects_a_path_escaping_session(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.ui_ocr("..", 5)
    assert result.error is not None
    assert result.error.code == "invalid_request"


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_ui_ocr_is_unsupported_off_windows(tmp_path: Path) -> None:
    service = _FakeUiService(
        _FakeWorker(capabilities={"debug.state"}, state=_RUNNING),
        artifact_root=tmp_path,
    )
    result = service.ui_ocr("s", 5)
    assert result.error is not None
    assert result.error.code == "unsupported_on_platform"


def test_ui_ocr_captures_and_registers(
    tmp_path: Path, _nt: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def ocr(
        hwnd: int,
        allowed: Any,
        path: Path,
        *,
        backend: str,
        language: str,
        client_only: bool,
    ) -> dict[str, Any]:
        path.write_bytes(b"BM")
        return {"text": "hi"}

    monkeypatch.setattr(svc_ui, "ocr_hwnd", ocr)
    monkeypatch.setattr(
        svc_ui,
        "_register_capture",
        lambda self, session_id, path, *, kind, source, payload: {"artifact_id": "b"},
    )
    service = _service(tmp_path, monkeypatch, state=_RUNNING)
    result = service.ui_ocr("s", 5)
    assert result.ok is True
    assert result.data is not None
    assert result.data["artifact_id"] == "b"
