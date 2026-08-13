"""M10.3 Gate: ui.drive_to_event with gui_fixture Transform UI goal."""

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


def _headless(architecture: Architecture) -> Path:
    key = (
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    )
    env = os.environ.get(key)
    if env and Path(env).is_file():
        return Path(env)
    fallback = _PROJECT_ROOT / "artifacts" / f"x64dbg-{architecture.value}" / "Release" / "headless.exe"
    if fallback.is_file():
        return fallback
    pytest.skip(f"headless missing for {architecture.value}")


def _gui(architecture: Architecture) -> Path:
    path = _PROJECT_ROOT / "artifacts" / f"fixtures-{architecture.value}" / "gui_fixture.exe"
    if path.is_file():
        return path
    pytest.skip(f"gui fixture missing: {path}")


def _sid(data: JsonObject | None) -> str:
    assert data and isinstance(data["session"], dict)
    return str(data["session"]["id"])


def _ok(result: object) -> JsonObject:
    assert getattr(result, "ok") is True, getattr(result, "error", None)
    data = getattr(result, "data")
    assert isinstance(data, dict)
    return data


def _fixture_transform(value: int) -> int:
    return (value ^ 0x5245) + 7


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize("architecture", [Architecture.X64, Architecture.X86])
def test_m10_ui_drive_to_event_transform(architecture: Architecture) -> None:
    if os.name != "nt":
        pytest.skip("requires Windows")
    os.environ[
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    ] = str(_headless(architecture))
    service = AnalysisService(Settings.load())
    session_id = _sid(_ok(service.create_session(str(_gui(architecture)))))
    try:
        _ok(service.open_dynamic(session_id))
        _ok(service.dynamic_launch(session_id, timeout=60.0))
        # Ensure window exists before drive.
        deadline = time.time() + 30
        while time.time() < deadline:
            st = _ok(service.dynamic_state(session_id))
            if st.get("state") == "paused":
                service.dynamic_resume(session_id, timeout=15.0)
            listed = _ok(service.ui_windows_list(session_id))
            if any(w.get("class_name") == "HeadlessReFixtureWindow" for w in listed["windows"]):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("gui window missing before drive")

        value = 7
        expected = _fixture_transform(value)
        driven = _ok(
            service.ui_drive_to_event(
                session_id,
                kind="debug.paused",
                accept_ui_goal=True,
                timeout=45.0,
                event_budget=4096,
                steps=[
                    {"action": "resolve", "class_name": "HeadlessReFixtureWindow", "as_root": True},
                    {
                        "action": "resolve",
                        "parent_from": "root",
                        "class_name": "Edit",
                        "control_id": 1001,
                    },
                    {"action": "text.set", "text": str(value)},
                    {
                        "action": "resolve",
                        "parent_from": "root",
                        "class_name": "Button",
                        "title": "Transform",
                    },
                    {"action": "click"},
                    {
                        "action": "wait",
                        "class_name": "HeadlessReFixtureWindow",
                        "title_contains": f"result {expected}",
                        "timeout": 15.0,
                    },
                ],
            )
        )
        assert driven["ui_goal"] is True
        assert driven["steps"]
    finally:
        service.close_session(session_id)
