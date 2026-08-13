"""M10.2 Gate: PID-bounded Win32 UI interact on gui_fixture."""

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


def _fixture_transform(value: int) -> int:
    return (value ^ 0x5245) + 7


def _ensure_gui_running(service: AnalysisService, session_id: str) -> JsonObject:
    deadline = time.time() + 30.0
    listed: JsonObject | None = None
    while time.time() < deadline:
        current = _service_data(service.dynamic_state(session_id))
        if current.get("state") == "paused":
            _service_data(service.dynamic_resume(session_id, timeout=30.0))
            # Win32 SendMessage* needs a live message pump; resume alone is not enough.
            running = service.dynamic_wait(session_id, "running", timeout=15.0)
            if running.ok:
                pass
        listed = _service_data(service.ui_windows_list(session_id))
        windows = listed["windows"]
        assert isinstance(windows, list)
        if any(w.get("class_name") == "HeadlessReFixtureWindow" for w in windows):
            return listed
        time.sleep(0.2)
    assert listed is not None
    raise AssertionError(f"gui_fixture window not observed: {listed}")


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize("architecture", [Architecture.X64, Architecture.X86])
def test_m10_ui_interact_transform_gate(architecture: Architecture) -> None:
    if os.name != "nt":
        pytest.skip("M10 UI interact gate requires Windows")
    headless = _headless_executable(architecture)
    fixture = _gui_fixture(architecture)
    env_key = (
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    )
    os.environ[env_key] = str(headless)

    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok, created
    session_id = _session_id(created.data)
    try:
        assert service.open_dynamic(session_id).ok
        assert service.dynamic_launch(session_id, timeout=60.0).ok
        _ensure_gui_running(service, session_id)

        root = _service_data(
            service.ui_resolve(
                session_id,
                class_name="HeadlessReFixtureWindow",
            )
        )["window"]
        assert isinstance(root, dict)
        root_hwnd = int(root["hwnd"])

        tree = _service_data(
            service.ui_tree(session_id, root_hwnd=root_hwnd, max_depth=2)
        )
        assert tree["count"] >= 2

        edit = _service_data(
            service.ui_resolve(
                session_id,
                parent_hwnd=root_hwnd,
                class_name="Edit",
                control_id=1001,
            )
        )["window"]
        button = _service_data(
            service.ui_resolve(
                session_id,
                parent_hwnd=root_hwnd,
                class_name="Button",
                title="Transform",
            )
        )["window"]
        assert isinstance(edit, dict) and isinstance(button, dict)

        value = 7
        expected = _fixture_transform(value)
        # Re-assert running immediately before synchronous WM_SETTEXT.
        state = _service_data(service.dynamic_state(session_id))
        if state.get("state") == "paused":
            _service_data(service.dynamic_resume(session_id, timeout=15.0))
            _service_data(service.dynamic_wait(session_id, "running", timeout=15.0))
        _service_data(
            service.ui_text_set(session_id, int(edit["hwnd"]), str(value))
        )
        _service_data(service.ui_click(session_id, int(button["hwnd"])))

        waited = _service_data(
            service.ui_wait(
                session_id,
                timeout=10.0,
                class_name="HeadlessReFixtureWindow",
                title_contains=f"result {expected}",
            )
        )
        assert waited["matched"] is True
        window = waited["window"]
        assert isinstance(window, dict)
        assert f"result {expected}" in str(window.get("title") or "")

        # ui.invoke whitelist path (command) must not crash; re-drive Transform.
        value2 = 9
        expected2 = _fixture_transform(value2)
        _service_data(service.ui_text_set(session_id, int(edit["hwnd"]), str(value2)))
        invoked = _service_data(
            service.ui_invoke(
                session_id,
                int(button["hwnd"]),
                action_name="command",
                control_id=1002,
            )
        )
        assert invoked["action"] == "invoke"
        waited2 = _service_data(
            service.ui_wait(
                session_id,
                timeout=10.0,
                class_name="HeadlessReFixtureWindow",
                title_contains=f"result {expected2}",
            )
        )
        assert waited2["matched"] is True

        # ui.screenshot: capture fixture root, enforce PID + non-empty BMP.
        shot = _service_data(service.ui_screenshot(session_id, root_hwnd))
        assert shot["hwnd"] == root_hwnd
        assert shot["pid"] == int(
            _service_data(service.dynamic_state(session_id))["debuggee_pid"]
        )
        assert shot["format"] == "bmp"
        assert shot["width"] > 0 and shot["height"] > 0
        assert shot["backend"] in {"win32_printwindow", "win32_bitblt"}
        artifact = Path(str(shot["artifact"]))
        assert artifact.is_file()
        assert artifact.suffix.casefold() == ".bmp"
        assert artifact.stat().st_size >= 54
        assert artifact.read_bytes()[:2] == b"BM"

        denied_shot = service.ui_screenshot(session_id, 0)
        assert not denied_shot.ok and denied_shot.error is not None
        assert denied_shot.error.code in {
            "invalid_params",
            "not_found",
            "permission_denied",
        }

        # Foreign hwnd must be rejected (MCP host console / desktop not allowed).
        denied = service.ui_click(session_id, 0)
        assert not denied.ok and denied.error is not None
        assert denied.error.code in {"invalid_params", "not_found", "permission_denied"}
    finally:
        service.close_session(session_id)
