"""Gate: the hidden Win32 desktop really hides a debuggee window from your desktop.

Starts x64dbg with hidden_desktop enabled, runs the GUI fixture under it, and
asserts the decisive property: the same PID has zero top-level windows on the
input desktop while the hidden-desktop snapshot sees the real window and can
capture it. Skips when a backend or fixture is missing; a skip is not a pass.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_CLASS = "HeadlessReFixtureWindow"


def _data(result: Result[JsonObject]) -> JsonObject:
    assert result.ok, result.model_dump(mode="json")
    assert result.data is not None
    return result.data


def _object(value: object) -> JsonObject:
    assert isinstance(value, dict)
    return {str(key): item for key, item in value.items()}


@pytest.fixture(scope="module")
def hidden_desktop_settings() -> Settings:
    loaded = Settings.load()
    executable = loaded.x64dbg_headless_x64
    if executable is None or not executable.is_file():
        pytest.skip("x64 headless executable is not configured")
    return replace(loaded, hidden_desktop=True)


@pytest.fixture(scope="module")
def gui_fixture() -> Path:
    binary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "gui_fixture.exe"
    if not binary.is_file():
        pytest.skip(f"fixture is not built: {binary}")
    return binary


def _run_until_hidden_window(
    service: AnalysisService,
    session_id: str,
    *,
    timeout: float = 40.0,
) -> JsonObject:
    """Keep the target running until its window is visible on the hidden desktop.

    x64dbg stops at the system breakpoint and again at the entry point, so a
    single resume never reaches the fixture's message loop. The fixture also
    creates the window without WS_VISIBLE and only then calls ShowWindow, so
    waiting for mere existence would race that gap.
    """
    deadline = time.monotonic() + timeout
    last: JsonObject = {}
    while time.monotonic() < deadline:
        state = service.dynamic_state(session_id)
        if state.ok and state.data is not None and state.data.get("state") == "paused":
            service.dynamic_resume(session_id)
        snapshot = service.virtual_desktop_snapshot(session_id)
        if snapshot.ok and snapshot.data is not None:
            last = snapshot.data
            for raw in last.get("windows") or []:
                window = _object(raw)
                if str(window.get("class_name")) == _FIXTURE_CLASS and window.get("visible"):
                    return last
        time.sleep(0.3)
    raise AssertionError(f"fixture window never appeared on the hidden desktop: {last}")


def _capture_until_rendered(
    service: AnalysisService,
    session_id: str,
    hwnd: int,
    *,
    timeout: float = 15.0,
) -> JsonObject:
    """Capture until the window has actually painted.

    A window that was created moments ago can still answer PrintWindow with a
    blank frame, which the capture correctly reports as degraded; retrying keeps
    the assertion strict without making it a race.
    """
    deadline = time.monotonic() + timeout
    last: JsonObject = {}
    while time.monotonic() < deadline:
        state = service.dynamic_state(session_id)
        if state.ok and state.data is not None and state.data.get("state") == "paused":
            service.dynamic_resume(session_id)
        captured = service.virtual_desktop_capture(session_id, hwnd=hwnd)
        if captured.ok and captured.data is not None:
            last = captured.data
            if last.get("degraded") is False:
                return last
        time.sleep(0.4)
    raise AssertionError(f"hidden-desktop window never rendered a frame: {last}")


def test_debuggee_window_is_hidden_from_the_input_desktop(
    hidden_desktop_settings: Settings,
    gui_fixture: Path,
) -> None:
    service = AnalysisService(hidden_desktop_settings)
    session_id = str(
        _object(_data(service.create_session(str(gui_fixture)))["session"])["id"]
    )
    try:
        _data(service.open_dynamic(session_id))
        launched = _data(service.dynamic_launch(session_id, timeout=60.0))
        assert _object(launched["state"])["state"] == "paused"

        # The window only exists once the fixture reaches its message loop, and
        # PrintWindow needs that loop pumping, so keep it running.
        snapshot = _run_until_hidden_window(service, session_id)

        assert snapshot["mode"] == "hidden_win32"
        assert snapshot["input_desktop"] is False
        assert str(snapshot["name"]).startswith("HeadlessRE-")
        windows = [_object(raw) for raw in snapshot["windows"]]
        target = next(item for item in windows if item["class_name"] == _FIXTURE_CLASS)
        assert "Headless RE Fixture" in str(target["title"])
        assert target["visible"] is True

        # The decisive property: the same PID owns nothing on the input desktop.
        on_input_desktop = _data(service.ui_windows_list(session_id))
        assert on_input_desktop["debuggee_pid"] == snapshot["debuggee_pid"]
        assert on_input_desktop["count"] == 0, on_input_desktop

        # A plain GDI window must render, otherwise degraded detection is wrong.
        captured = _capture_until_rendered(service, session_id, int(target["hwnd"]))
        artifact = Path(str(captured["path"]))
        assert artifact.is_file()
        assert artifact.read_bytes()[:2] == b"BM"
        assert captured["width"] > 0 and captured["height"] > 0
        assert captured["degraded"] is False, captured
        assert captured["intrusion"] == "on_demand_printwindow"

        _data(service.dynamic_stop(session_id, timeout=60.0))
    finally:
        service.close_session(session_id)
        service.close_all()
