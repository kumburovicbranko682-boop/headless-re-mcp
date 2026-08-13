"""M10.1 Gate: debuggee PID contract + ui.windows.list PID boundary."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.core.service import AnalysisService, JsonObject

# These gates enumerate and click real windows on the desktop this process
# owns, so they cannot see a debuggee running on a hidden desktop.
pytestmark = pytest.mark.visible_desktop

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _headless_executable(architecture: Architecture) -> Path:
    env_key = (
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    )
    configured = os.environ.get(env_key)
    if configured:
        path = Path(configured)
        if path.is_file():
            return path
        pytest.skip(f"{env_key} missing: {path}")
    settings = Settings.load()
    from_settings = (
        settings.x64dbg_headless_x64
        if architecture is Architecture.X64
        else settings.x64dbg_headless_x86
    )
    if from_settings is not None and from_settings.is_file():
        return from_settings
    fallback = (
        _PROJECT_ROOT
        / "artifacts"
        / f"x64dbg-{architecture.value}"
        / "Release"
        / "headless.exe"
    )
    if fallback.is_file():
        return fallback
    pytest.skip(f"x64dbg headless not configured for {architecture.value}")


def _gui_fixture(architecture: Architecture) -> Path:
    fixture = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "gui_fixture.exe"
    )
    if fixture.is_file():
        return fixture
    pytest.skip(f"gui fixture missing: {fixture}")


def _session_id(data: JsonObject | None) -> str:
    assert data is not None
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _service_data(result: object) -> JsonObject:
    ok = getattr(result, "ok", None)
    data = getattr(result, "data", None)
    error = getattr(result, "error", None)
    assert ok is True, error
    assert isinstance(data, dict)
    return data


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize(
    "architecture",
    [Architecture.X64, Architecture.X86],
)
def test_m10_ui_pid_boundary_gate(architecture: Architecture) -> None:
    if os.name != "nt":
        pytest.skip("M10 UI PID gate requires Windows")
    headless = _headless_executable(architecture)
    fixture = _gui_fixture(architecture)
    env_key = (
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    )
    os.environ[env_key] = str(headless)

    settings = Settings.load()
    service = AnalysisService(settings)
    created = service.create_session(str(fixture))
    assert created.ok, created
    session_id = _session_id(created.data)
    try:
        opened = _service_data(service.open_dynamic(session_id))
        backend = opened["backend"]
        assert isinstance(backend, dict)
        debugger_pid = backend.get("pid")
        if debugger_pid is None:
            # worker metadata may omit pid; fall back after state annotate
            debugger_pid = None

        idle = _service_data(service.dynamic_state(session_id))
        assert idle["state"] == "idle"
        assert idle["debuggee_pid"] is None
        assert idle["debugger_pid"] is not None
        assert idle["debugger_pid"] != 0
        if debugger_pid is None:
            debugger_pid = idle["debugger_pid"]
        assert idle["debugger_pid"] == debugger_pid

        refused = service.ui_windows_list(session_id)
        assert not refused.ok and refused.error is not None
        assert refused.error.code == "invalid_state"

        launched = _service_data(service.dynamic_launch(session_id, timeout=60.0))
        state = launched.get("state")
        assert isinstance(state, dict)
        # launch envelope may not yet include annotated fields; re-read state
        active = _service_data(service.dynamic_state(session_id))
        debuggee_pid = active["debuggee_pid"]
        assert isinstance(debuggee_pid, int) and debuggee_pid > 0
        assert active["debugger_pid"] == debugger_pid
        assert debuggee_pid != debugger_pid

        # Headless stops at system/entry breakpoints; keep resuming until the
        # GUI fixture creates its top-level window (or we time out).
        deadline = time.time() + 60.0
        listed: JsonObject | None = None
        matched = False
        while time.time() < deadline:
            current = _service_data(service.dynamic_state(session_id))
            if current.get("state") == "paused":
                resumed = service.dynamic_resume(session_id, timeout=30.0)
                assert resumed.ok, resumed
            elif current.get("state") == "idle":
                # Unexpected idle before window; relaunch is not allowed — keep polling.
                time.sleep(0.2)
                continue
            payload = _service_data(service.ui_windows_list(session_id))
            listed = payload
            assert payload["debuggee_pid"] == debuggee_pid
            assert payload["debugger_pid"] == debugger_pid
            assert payload["allowed_pids"] == [debuggee_pid]
            assert debugger_pid in payload["blocked_pids"]
            assert os.getpid() in payload["blocked_pids"]
            windows = payload["windows"]
            assert isinstance(windows, list)
            for window in windows:
                assert window["pid"] == debuggee_pid
                assert window["pid"] != debugger_pid
                assert window["pid"] != os.getpid()
            if any(
                window.get("class_name") == "HeadlessReFixtureWindow"
                or "Headless RE Fixture" in str(window.get("title") or "")
                for window in windows
            ):
                matched = True
                break
            time.sleep(0.15)

        assert listed is not None
        assert matched, f"gui_fixture window not observed: {listed}"

        blocked = service.ui_windows_list(
            session_id,
            allow_child_pids=[int(debugger_pid)],
        )
        assert not blocked.ok and blocked.error is not None
        assert blocked.error.code == "permission_denied"

        blocked_host = service.ui_windows_list(
            session_id,
            allow_child_pids=[os.getpid()],
        )
        assert not blocked_host.ok and blocked_host.error is not None
        assert blocked_host.error.code == "permission_denied"
    finally:
        service.close_session(session_id)
