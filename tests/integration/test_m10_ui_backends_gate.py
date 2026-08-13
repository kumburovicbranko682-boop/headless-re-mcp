"""M10.2 Gate: UIA tree/click, OCR, and SendInput foreground PID path."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.core.ui_ocr import windows_ocr_available
from headless_re_mcp.core.ui_uia import uia_available

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
    if configured and Path(configured).is_file():
        return Path(configured)
    fallback = (
        _PROJECT_ROOT
        / "artifacts"
        / f"x64dbg-{architecture.value}"
        / "Release"
        / "headless.exe"
    )
    if fallback.is_file():
        return fallback
    pytest.skip(f"x64dbg headless missing for {architecture.value}")


def _gui_fixture(architecture: Architecture) -> Path:
    fixture = (
        _PROJECT_ROOT / "artifacts" / f"fixtures-{architecture.value}" / "gui_fixture.exe"
    )
    if fixture.is_file():
        return fixture
    pytest.skip(f"gui fixture missing: {fixture}")


def _session_id(data: JsonObject | None) -> str:
    assert data is not None
    return str(data["session"]["id"])


def _data(result: object) -> JsonObject:
    assert getattr(result, "ok", None) is True, getattr(result, "error", None)
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _ensure_gui(service: AnalysisService, session_id: str) -> None:
    deadline = time.time() + 30.0
    while time.time() < deadline:
        state = _data(service.dynamic_state(session_id))
        if state.get("state") == "paused":
            _data(service.dynamic_resume(session_id, timeout=30.0))
            service.dynamic_wait(session_id, "running", timeout=15.0)
        listed = _data(service.ui_windows_list(session_id))
        if any(w.get("class_name") == "HeadlessReFixtureWindow" for w in listed["windows"]):
            return
        time.sleep(0.2)
    raise AssertionError("gui_fixture window not observed")


def _fixture_transform(value: int) -> int:
    return (value ^ 0x5245) + 7


@pytest.mark.integration
@pytest.mark.headless
def test_m10_ui_uia_ocr_sendinput_gate() -> None:
    if os.name != "nt":
        pytest.skip("Windows only")
    if not uia_available():
        pytest.fail("uiautomation package required for UIA Gate (skip≠pass)")
    if not windows_ocr_available():
        pytest.fail("Windows.Media.Ocr required for OCR Gate (skip≠pass)")

    architecture = Architecture.X64
    headless = _headless_executable(architecture)
    fixture = _gui_fixture(architecture)
    os.environ["HEADLESS_RE_X64DBG_HEADLESS_X64"] = str(headless)

    service = AnalysisService(Settings.load())
    created = service.create_session(str(fixture))
    assert created.ok, created.error
    session_id = _session_id(created.data)
    try:
        assert service.open_dynamic(session_id).ok
        assert service.dynamic_launch(session_id, timeout=60.0).ok
        _ensure_gui(service, session_id)

        root = _data(
            service.ui_resolve(session_id, class_name="HeadlessReFixtureWindow")
        )["window"]
        root_hwnd = int(root["hwnd"])

        ocr = _data(service.ui_ocr(session_id, root_hwnd, backend="windows", language="en-US"))
        assert ocr.get("ocr_backend") == "windows_ocr"
        text = str(ocr.get("text") or "")
        folded = text.casefold()
        assert ('transform' in folded) or ('fixture' in folded), text

        uia_tree = _data(
            service.ui_tree(
                session_id,
                root_hwnd=root_hwnd,
                max_depth=3,
                backend="uia",
            )
        )
        assert uia_tree.get("backend") == "uia"
        assert int(uia_tree.get("count") or 0) >= 2

        edit = _data(
            service.ui_resolve(
                session_id,
                parent_hwnd=root_hwnd,
                class_name="Edit",
                control_id=1001,
            )
        )["window"]
        button = _data(
            service.ui_resolve(
                session_id,
                parent_hwnd=root_hwnd,
                class_name="Button",
                title="Transform",
            )
        )["window"]

        value = 11
        expected = _fixture_transform(value)
        state = _data(service.dynamic_state(session_id))
        if state.get("state") == "paused":
            _data(service.dynamic_resume(session_id, timeout=15.0))
            _data(service.dynamic_wait(session_id, "running", timeout=15.0))

        # Prefer UIA value + Invoke; then SendInput click as last-resort path.
        try:
            _data(
                service.ui_text_set(
                    session_id,
                    int(edit["hwnd"]),
                    str(value),
                    backend="uia",
                )
            )
        except AssertionError:
            _data(service.ui_text_set(session_id, int(edit["hwnd"]), str(value)))

        clicked = _data(
            service.ui_click(session_id, int(button["hwnd"]), backend="uia")
        )
        assert "uia" in str(clicked.get("backend") or "")

        waited = _data(
            service.ui_wait(
                session_id,
                timeout=10.0,
                class_name="HeadlessReFixtureWindow",
                title_contains=f"result {expected}",
            )
        )
        if not waited.get("matched"):
            # Retry with SendInput click path (foreground PID re-check).
            value2 = 13
            expected2 = _fixture_transform(value2)
            _data(service.ui_text_set(session_id, int(edit["hwnd"]), str(value2)))
            send = _data(
                service.ui_click(session_id, int(button["hwnd"]), backend="sendinput")
            )
            assert send.get("backend") == "sendinput"
            assert int(send.get("foreground_pid") or 0) == int(
                _data(service.dynamic_state(session_id))["debuggee_pid"]
            )
            waited = _data(
                service.ui_wait(
                    session_id,
                    timeout=10.0,
                    class_name="HeadlessReFixtureWindow",
                    title_contains=f"result {expected2}",
                )
            )
            assert waited.get("matched") is True
        else:
            # Explicitly exercise SendInput once more with a new value.
            value2 = 17
            expected2 = _fixture_transform(value2)
            state = _data(service.dynamic_state(session_id))
            if state.get("state") == "paused":
                _data(service.dynamic_resume(session_id, timeout=15.0))
                _data(service.dynamic_wait(session_id, "running", timeout=15.0))
            _data(service.ui_text_set(session_id, int(edit["hwnd"]), str(value2)))
            send = _data(
                service.ui_click(session_id, int(button["hwnd"]), backend="sendinput")
            )
            assert send.get("backend") == "sendinput"
            assert int(send.get("foreground_pid") or 0) > 0
            waited2 = _data(
                service.ui_wait(
                    session_id,
                    timeout=10.0,
                    class_name="HeadlessReFixtureWindow",
                    title_contains=f"result {expected2}",
                )
            )
            assert waited2.get("matched") is True
    finally:
        service.close_session(session_id)
