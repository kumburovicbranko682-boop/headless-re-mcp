"""The PID-bounded UI automation surface, driven as if it were on Windows.

Every entry point in ``UiAutomationMixin`` gates on ``os.name == "nt"`` and then
shells out to the Win32/UIA helpers, so on a hosted Linux runner the whole body
is dead code behind an ``unsupported_on_platform`` short-circuit. These tests
pin ``os.name`` to ``"nt"`` and stand fakes in for the imported Win32/UIA
helpers, so the shared ``_ui_call`` machinery -- capability gating, PID
resolution, the paused-debuggee resume, the PID-boundary translation, and
capture registration -- runs for real. The pure helpers (snapshot annotation,
window selection, finalize) are exercised directly and run on any platform.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core import service_ui
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ui import (
    _annotate_virtual_desktop_snapshot,
    _as_positive_pid,
    _desktop_monitor_pids,
    _select_desktop_window,
    _ui_finalize_windows,
)
from headless_re_mcp.core.windows import UiPidBoundaryError
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _state,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]

DEBUGGEE_PID = 7100
DEBUGGER_PID = 7000


class FakeUiWorker(FakeDynamicWorker):
    """A dynamic worker that also exposes the hidden-desktop capture surface."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.snapshot_payload: JsonObject = {
            "available": True,
            "windows": [
                {
                    "hwnd": 222,
                    "pid": DEBUGGEE_PID,
                    "area": 800 * 600,
                    "visible": True,
                    "minimized": False,
                    "title": "app",
                    "rect": {"width": 800, "height": 600},
                }
            ],
            "desktop_window_count": 1,
        }

    def desktop_snapshot(self, *, allowed_pids: frozenset[int]) -> JsonObject:
        self.requests.append(("desktop_snapshot", {"allowed": sorted(allowed_pids)}))
        return dict(self.snapshot_payload)

    def desktop_capture(
        self, hwnd: int, *, allowed_pids: frozenset[int], output_path: Path
    ) -> JsonObject:
        self.requests.append(("desktop_capture", {"hwnd": hwnd}))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"BM" + b"\x00" * 20)
        return {"hwnd": hwnd, "output_path": str(output_path), "bytes": 22}


def _window(hwnd: int = 111, pid: int = DEBUGGEE_PID) -> JsonObject:
    return {"hwnd": hwnd, "pid": pid, "title": "w", "class": "C"}


def _install_win32_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every imported Win32/UIA helper at a deterministic fake."""
    # NOTE: os is a shared module object, so this flips os.name process-wide for
    # the duration of the test. Any real Win32-branching helper the flows reach
    # (process_tree enumeration, PID liveness) is faked below so nothing dips
    # into ctypes.windll.
    monkeypatch.setattr("headless_re_mcp.core.service_ui.os.name", "nt")
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children",
        lambda _pid, **_kw: [],
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.process_image_path",
        lambda _pid: "C:/fixture.exe",
    )
    monkeypatch.setattr(
        service_ui,
        "resolve_allowed_ui_pids",
        lambda **_kw: (frozenset({DEBUGGEE_PID}), frozenset({DEBUGGER_PID})),
    )
    monkeypatch.setattr(service_ui, "is_pid_alive", lambda _pid: True)
    monkeypatch.setattr(service_ui, "list_windows_for_pids", lambda _pids: [_window()])
    monkeypatch.setattr(service_ui, "resolve_hwnd", lambda _allowed, **_kw: _window())
    monkeypatch.setattr(
        service_ui,
        "build_window_tree",
        lambda _roots, _allowed, **_kw: {"tree": {"hwnd": 111}, "node_count": 1},
    )
    monkeypatch.setattr(
        service_ui,
        "build_uia_tree",
        lambda _root, _allowed, **_kw: {"tree": {"name": "root"}, "node_count": 1},
    )
    monkeypatch.setattr(service_ui, "uia_available", lambda: True)
    monkeypatch.setattr(
        service_ui, "click_hwnd", lambda *_a, **_kw: {"hwnd": 111, "backend": "win32"}
    )
    monkeypatch.setattr(
        service_ui, "click_hwnd_uia", lambda *_a, **_kw: {"hwnd": 111, "backend": "uia"}
    )
    monkeypatch.setattr(
        service_ui,
        "click_hwnd_sendinput",
        lambda *_a, **_kw: {"hwnd": 111, "backend": "sendinput"},
    )
    monkeypatch.setattr(
        service_ui, "click_hwnd_at", lambda *_a, **_kw: {"hwnd": 111, "x": 5, "y": 6}
    )
    monkeypatch.setattr(
        service_ui, "close_hwnd", lambda *_a, **_kw: {"hwnd": 111, "closed": True}
    )
    monkeypatch.setattr(
        service_ui, "set_window_text", lambda *_a, **_kw: {"hwnd": 111, "backend": "win32"}
    )
    monkeypatch.setattr(
        service_ui, "set_value_uia", lambda *_a, **_kw: {"hwnd": 111, "backend": "uia"}
    )
    monkeypatch.setattr(
        service_ui, "send_key", lambda *_a, **_kw: {"hwnd": 111, "backend": "win32"}
    )
    monkeypatch.setattr(
        service_ui,
        "send_key_sendinput",
        lambda *_a, **_kw: {"hwnd": 111, "backend": "sendinput"},
    )
    monkeypatch.setattr(
        service_ui, "invoke_hwnd", lambda *_a, **_kw: {"hwnd": 111, "invoked": True}
    )
    monkeypatch.setattr(
        service_ui, "wait_for_window", lambda *_a, **_kw: {"hwnd": 111, "found": True}
    )

    def _capture(_hwnd: int, _allowed: frozenset[int], path: Path, **_kw: Any) -> JsonObject:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"BM" + b"\x00" * 40)
        return {"hwnd": _hwnd, "artifact_path": str(path), "bytes": 42}

    def _ocr(_hwnd: int, _allowed: frozenset[int], path: Path, **_kw: Any) -> JsonObject:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"BM" + b"\x00" * 40)
        return {"hwnd": _hwnd, "artifact_path": str(path), "text": "hello"}

    monkeypatch.setattr(service_ui, "capture_hwnd_screenshot", _capture)
    monkeypatch.setattr(service_ui, "ocr_hwnd", _ocr)


@pytest.fixture
def nt_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[AnalysisService, str, FakeUiWorker]]:
    worker = FakeUiWorker()
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    _install_win32_fakes(monkeypatch)
    try:
        yield service, session_id, worker
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# pure helpers (platform-independent)
# --------------------------------------------------------------------------


def test_as_positive_pid_parses_ints_and_strings() -> None:
    assert _as_positive_pid(42) == 42
    assert _as_positive_pid("42") == 42
    assert _as_positive_pid(0) is None
    assert _as_positive_pid(-1) is None
    assert _as_positive_pid("0") is None
    assert _as_positive_pid("abc") is None
    assert _as_positive_pid(None) is None


def test_desktop_monitor_pids_ignores_a_dead_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ui, "is_pid_alive", lambda _pid: False)
    allowed, debuggee = _desktop_monitor_pids({"process_id": 4242})
    assert allowed == frozenset()
    assert debuggee is None


def test_desktop_monitor_pids_includes_a_live_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ui, "is_pid_alive", lambda pid: pid in {4242, 4243})
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children",
        lambda _pid: [4243, 9999],
    )
    allowed, debuggee = _desktop_monitor_pids({"debuggee_pid": 4242, "state": "running"})
    assert debuggee == 4242
    assert allowed == frozenset({4242, 4243})


def test_annotate_snapshot_normalizes_non_list_windows() -> None:
    payload = _annotate_virtual_desktop_snapshot(
        {"windows": "nope", "desktop_window_count": "many"},
        session_id="s1",
        state={"state": "running"},
        allowed=frozenset({7100}),
        debuggee_pid=7100,
        debugger_pid=7000,
    )
    assert payload["windows"] == []
    assert payload["window_count"] == 0
    assert payload["desktop_window_count"] == 0
    assert payload["hint"] == "no_debuggee_windows"


def test_annotate_snapshot_idle_hint() -> None:
    payload = _annotate_virtual_desktop_snapshot(
        {"windows": [], "desktop_window_count": 0},
        session_id="s1",
        state={"state": "idle"},
        allowed=frozenset(),
        debuggee_pid=None,
        debugger_pid=None,
    )
    assert payload["hint"] == "debuggee_idle"
    assert "Launch or attach" in str(payload["suggestion"])


def test_annotate_snapshot_keeps_windows_without_a_hint() -> None:
    payload = _annotate_virtual_desktop_snapshot(
        {"windows": [{"hwnd": 1}], "desktop_window_count": 1},
        session_id="s1",
        state={"state": "running"},
        allowed=frozenset({7100}),
        debuggee_pid=7100,
        debugger_pid=7000,
    )
    assert payload["window_count"] == 1
    assert "hint" not in payload


def test_select_desktop_window_by_requested_hwnd() -> None:
    rows = [{"hwnd": 1}, {"hwnd": 2}]
    assert _select_desktop_window(rows, 2)["hwnd"] == 2


def test_select_desktop_window_rejects_a_bad_requested_hwnd() -> None:
    with pytest.raises(ValueError, match="hwnd must be a positive integer"):
        _select_desktop_window([{"hwnd": 1}], 0)


def test_select_desktop_window_missing_requested_hwnd() -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _select_desktop_window([{"hwnd": 1}], 999)
    assert excinfo.value.code == "not_found"


def test_select_desktop_window_empty_desktop() -> None:
    with pytest.raises(XdbgRpcError) as excinfo:
        _select_desktop_window([], None)
    assert excinfo.value.code == "not_found"


def test_ui_finalize_windows_normalizes_and_counts() -> None:
    ctx: JsonObject = {"allowed": frozenset({7100}), "debuggee_pid": 7100}
    payload = _ui_finalize_windows({"windows": "nope"}, ctx)
    assert payload["windows"] == []
    assert payload["count"] == 0


def test_ui_finalize_windows_skips_non_dict_rows() -> None:
    ctx: JsonObject = {"allowed": frozenset({7100}), "debuggee_pid": 0}
    payload = _ui_finalize_windows({"windows": ["nope", {"pid": 7100}]}, ctx)
    assert payload["count"] == 2


def test_ui_finalize_windows_refuses_a_foreign_pid() -> None:
    ctx: JsonObject = {"allowed": frozenset({7100}), "debuggee_pid": 7100}
    with pytest.raises(UiPidBoundaryError):
        _ui_finalize_windows({"windows": [{"pid": 4242}]}, ctx)


def test_ui_finalize_windows_suggests_child_pids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ui, "is_pid_alive", lambda _pid: True)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates",
        lambda _pid, list_windows_fn=None: [{"pid": 8000}],
    )
    ctx: JsonObject = {"allowed": frozenset({7100}), "debuggee_pid": 7100}
    payload = _ui_finalize_windows({"windows": []}, ctx)
    assert payload["hint"] == "windows_on_child_pids"
    assert payload["suggested_child_pids"] == [8000]


def test_ui_finalize_windows_tolerates_a_child_probe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service_ui, "is_pid_alive", lambda _pid: True)

    def _boom(_pid: int, list_windows_fn: Any = None) -> Any:
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates", _boom
    )
    ctx: JsonObject = {"allowed": frozenset({7100}), "debuggee_pid": 7100}
    payload = _ui_finalize_windows({"windows": []}, ctx)
    assert "child_candidates" not in payload


def test_ui_finalize_windows_hidden_desktop_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ui, "is_pid_alive", lambda _pid: False)
    ctx: JsonObject = {"allowed": frozenset({7100}), "debuggee_pid": 7100}
    payload = _ui_finalize_windows({"windows": []}, ctx, hidden_desktop=True)
    assert payload["hint"] == "windows_on_hidden_desktop"


# --------------------------------------------------------------------------
# platform gate
# --------------------------------------------------------------------------


@pytest.fixture
def linux_env(tmp_path: Path) -> Iterator[tuple[AnalysisService, str, FakeUiWorker]]:
    worker = FakeUiWorker()
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    try:
        yield service, session_id, worker
    finally:
        service.close_all()


@pytest.mark.parametrize(
    "call",
    [
        lambda svc, sid: svc.ui_click(sid, 111),
        lambda svc, sid: svc.virtual_desktop_snapshot(sid),
        lambda svc, sid: svc.virtual_desktop_capture(sid),
        lambda svc, sid: svc.ui_screenshot(sid, 111),
        lambda svc, sid: svc.ui_ocr(sid, 111),
    ],
)
def test_ui_entrypoints_are_unsupported_off_windows(
    linux_env: tuple[AnalysisService, str, FakeUiWorker],
    call: Any,
) -> None:
    service, sid, _ = linux_env
    result = call(service, sid)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unsupported_on_platform"


# --------------------------------------------------------------------------
# virtual desktop
# --------------------------------------------------------------------------


def test_virtual_desktop_snapshot_annotates(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, _ = nt_env
    result = service.virtual_desktop_snapshot(sid)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["capture_mode"] == "passive"
    assert result.data["debuggee_pid"] == DEBUGGEE_PID


def test_virtual_desktop_snapshot_without_capability(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, worker = nt_env
    monkeypatch.delattr(type(worker), "desktop_snapshot", raising=False)
    result = service.virtual_desktop_snapshot(sid)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_virtual_desktop_capture_writes_a_bitmap(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, worker = nt_env
    result = service.virtual_desktop_capture(sid)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["window"]["hwnd"] == 222
    assert result.data["intrusion"] == "on_demand_printwindow"
    assert str(result.data["output_path"]).endswith("window-222.bmp")
    assert any(cmd == "desktop_capture" for cmd, _ in worker.requests)


def test_virtual_desktop_snapshot_rejects_a_non_object(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, worker = nt_env
    worker.desktop_snapshot = lambda **_kw: []  # type: ignore[method-assign,assignment]
    result = service.virtual_desktop_snapshot(sid)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_virtual_desktop_capture_rejects_a_non_object(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, worker = nt_env
    worker.desktop_capture = lambda *_a, **_kw: []  # type: ignore[method-assign,assignment]
    result = service.virtual_desktop_capture(sid)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_virtual_desktop_capture_without_capability(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, worker = nt_env
    monkeypatch.delattr(type(worker), "desktop_capture", raising=False)
    result = service.virtual_desktop_capture(sid)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


# --------------------------------------------------------------------------
# _ui_call-driven methods
# --------------------------------------------------------------------------


def test_ui_windows_list_end_to_end(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, _ = nt_env
    result = service.ui_windows_list(sid)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["count"] == 1


def test_ui_process_tree(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = nt_env
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children",
        lambda _pid: [8000],
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.process_image_path",
        lambda _pid: "C:/app.exe",
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates",
        lambda _pid, list_windows_fn=None: [{"pid": 8000}],
    )
    result = service.ui_process_tree(sid)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["debuggee_pid"] == DEBUGGEE_PID
    assert result.data["children"][0]["pid"] == 8000


def test_ui_tree_win32(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_tree(sid)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["backend"] == "win32_enum"


def test_ui_tree_win32_with_root(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_tree(sid, root_hwnd=111)
    assert result.ok, result.error


def test_ui_tree_uia_requires_root(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_tree(sid, backend="uia")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_ui_tree_uia_with_root(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_tree(sid, backend="uia", root_hwnd=111)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["tree"]["name"] == "root"


def test_ui_resolve(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["window"]["hwnd"] == 111


@pytest.mark.parametrize("backend", ["win32", "uia", "sendinput"])
def test_ui_click_backends(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], backend: str
) -> None:
    service, sid, _ = nt_env
    result = service.ui_click(sid, 111, backend=backend)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["backend"] == backend


def test_ui_click_at(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_click_at(sid, 111, 5, 6)
    assert result.ok, result.error


def test_ui_window_close(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_window_close(sid, 111)
    assert result.ok, result.error


@pytest.mark.parametrize("backend", ["win32", "uia"])
def test_ui_text_set_backends(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], backend: str
) -> None:
    service, sid, _ = nt_env
    result = service.ui_text_set(sid, 111, "hello", backend=backend)
    assert result.ok, result.error


@pytest.mark.parametrize("backend", ["win32", "sendinput"])
def test_ui_key_backends(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], backend: str
) -> None:
    service, sid, _ = nt_env
    result = service.ui_key(sid, 111, text="a", backend=backend)
    assert result.ok, result.error


def test_ui_invoke(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_invoke(sid, 111, action_name="click")
    assert result.ok, result.error


def test_ui_wait(nt_env: tuple[AnalysisService, str, FakeUiWorker]) -> None:
    service, sid, _ = nt_env
    result = service.ui_wait(sid, timeout=0.1, title="w")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["backend"] == "win32_poll"


def test_ui_screenshot_registers_a_capture(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, _ = nt_env
    result = service.ui_screenshot(sid, 111)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data.get("artifact_id")


def test_ui_screenshot_without_a_written_file_skips_registration(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = nt_env
    # Capture reports success but writes nothing: there is no artifact to
    # register, so the payload passes through untouched.
    monkeypatch.setattr(
        service_ui,
        "capture_hwnd_screenshot",
        lambda *_a, **_kw: {"hwnd": 111, "note": "no bytes"},
    )
    result = service.ui_screenshot(sid, 111)
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_ui_screenshot_rejects_a_hostile_session_id(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, _, _ = nt_env
    result = service.ui_screenshot("../escape", 111)
    assert result.ok is False
    assert result.error is not None


def test_ui_ocr_registers_a_capture(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, _ = nt_env
    result = service.ui_ocr(sid, 111)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data.get("artifact_id")
    assert result.data["text"] == "hello"


def test_ui_ocr_rejects_a_hostile_session_id(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, _, _ = nt_env
    result = service.ui_ocr("../escape", 111)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# _ui_call edge cases
# --------------------------------------------------------------------------


def test_ui_call_requires_debug_state_capability(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, worker = nt_env
    reduced = worker.capabilities - {"debug.state"}
    monkeypatch.setattr(type(worker), "capabilities", property(lambda self: reduced))
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_ui_call_refuses_without_a_live_debuggee(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, worker = nt_env
    worker.current_state = _state("idle")
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_ui_call_resumes_a_paused_debuggee_before_interacting(
    nt_env: tuple[AnalysisService, str, FakeUiWorker],
) -> None:
    service, sid, worker = nt_env
    worker.current_state = _state("paused")
    result = service.ui_click(sid, 111)
    assert result.ok, result.error
    assert ("debug.resume", {}) in worker.requests


def test_ui_call_tolerates_a_resume_timeout(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, worker = nt_env
    worker.current_state = _state("paused")

    def _timeout(*_a: Any, **_kw: Any) -> JsonObject:
        raise XdbgRpcError("timeout", "still paused")

    monkeypatch.setattr(type(worker), "wait_for_state", _timeout)
    result = service.ui_click(sid, 111)
    # A resume timeout is non-fatal: the click proceeds via PostMessage.
    assert result.ok, result.error


def test_ui_call_maps_a_failed_resume(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, worker = nt_env
    worker.current_state = _state("paused")

    def _hard_fail(*_a: Any, **_kw: Any) -> JsonObject:
        raise XdbgRpcError("worker_crashed", "resume broke")

    monkeypatch.setattr(type(worker), "wait_for_state", _hard_fail)
    result = service.ui_click(sid, 111)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "resume_failed"


def test_ui_call_maps_a_pid_boundary_error_from_resolution(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = nt_env

    def _boundary(**_kw: Any) -> Any:
        raise UiPidBoundaryError("permission_denied", "escaped", pid=4242, allowed_pids=[7100])

    monkeypatch.setattr(service_ui, "resolve_allowed_ui_pids", _boundary)
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "permission_denied"


def test_ui_call_maps_a_pid_boundary_error_from_the_action(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = nt_env

    def _boundary(_allowed: frozenset[int], **_kw: Any) -> Any:
        raise UiPidBoundaryError("permission_denied", "escaped", pid=4242, allowed_pids=[7100])

    monkeypatch.setattr(service_ui, "resolve_hwnd", _boundary)
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "permission_denied"
    assert result.error.details.get("debuggee_pid") == DEBUGGEE_PID


def test_ui_call_surfaces_an_unexpected_action_error(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = nt_env

    def _boom(_allowed: frozenset[int], **_kw: Any) -> Any:
        raise RuntimeError("resolve blew up")

    monkeypatch.setattr(service_ui, "resolve_hwnd", _boom)
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok is False
    assert result.error is not None


def test_ui_call_fails_the_runtime_on_a_fatal_error(
    nt_env: tuple[AnalysisService, str, FakeUiWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid, _ = nt_env

    def _fatal(_allowed: frozenset[int], **_kw: Any) -> Any:
        raise XdbgRpcError("rpc_protocol_error", "worker desynced")

    monkeypatch.setattr(service_ui, "resolve_hwnd", _fatal)
    result = service.ui_resolve(sid, hwnd=111)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "rpc_protocol_error"
    # A fatal worker error marks the backend runtime failed.
    runtime = service._runtime_owner.get(sid, BackendKind.X64DBG)
    assert runtime is None or getattr(runtime, "failed", False)
