"""M10.3 Gate: ui.drive_to_breakpoint reaches a workflow intent via real UI."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject

# These gates enumerate and click real windows on the desktop this process
# owns, so they cannot see a debuggee running on a hidden desktop.
pytestmark = pytest.mark.visible_desktop

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_INTENT_ID = "gui-transform"
_MODULE_KEY = "gui-fixture"


def _headless(architecture: Architecture) -> Path:
    key = (
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    )
    configured = os.environ.get(key)
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
    pytest.skip(f"headless missing for {architecture.value}")


def _gui(architecture: Architecture) -> Path:
    path = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "gui_fixture.exe"
    )
    if path.is_file():
        return path
    pytest.skip(f"gui fixture missing: {path}")


def _ok(result: Result[JsonObject]) -> JsonObject:
    assert result.ok is True, result.error
    data = result.data
    assert isinstance(data, dict)
    return data


def _session_id(data: JsonObject) -> str:
    session = data.get("session")
    assert isinstance(session, dict)
    return str(session["id"])


def _read_u16(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset : offset + 2], "little")


def _read_u32(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset : offset + 4], "little")


def _export_rva(binary: Path, symbol: str) -> int:
    image = binary.read_bytes()
    pe_offset = _read_u32(image, 0x3C)
    assert image[pe_offset : pe_offset + 4] == b"PE\0\0"
    section_count = _read_u16(image, pe_offset + 6)
    optional_size = _read_u16(image, pe_offset + 20)
    optional = pe_offset + 24
    magic = _read_u16(image, optional)
    assert magic in {0x10B, 0x20B}
    directory_offset = optional + (96 if magic == 0x10B else 112)
    export_rva = _read_u32(image, directory_offset)
    assert export_rva > 0
    section_table = optional + optional_size

    def rva_to_offset(rva: int) -> int:
        for index in range(section_count):
            section = section_table + index * 40
            virtual_size = _read_u32(image, section + 8)
            virtual_address = _read_u32(image, section + 12)
            raw_size = _read_u32(image, section + 16)
            raw_offset = _read_u32(image, section + 20)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_offset + rva - virtual_address
        raise AssertionError(f"RVA 0x{rva:X} is outside PE sections")

    export = rva_to_offset(export_rva)
    function_count = _read_u32(image, export + 20)
    name_count = _read_u32(image, export + 24)
    function_table = rva_to_offset(_read_u32(image, export + 28))
    name_table = rva_to_offset(_read_u32(image, export + 32))
    ordinal_table = rva_to_offset(_read_u32(image, export + 36))
    candidates = {
        symbol,
        f"_{symbol}",
        f"_{symbol}@4",
        f"{symbol}@4",
    }

    for index in range(name_count):
        name_offset = rva_to_offset(_read_u32(image, name_table + index * 4))
        end = image.index(b"\0", name_offset)
        name = image[name_offset:end].decode("ascii")
        if name not in candidates:
            continue
        ordinal = _read_u16(image, ordinal_table + index * 2)
        assert ordinal < function_count
        resolved = _read_u32(image, function_table + ordinal * 4)
        assert resolved > 0
        return resolved
    raise AssertionError(f"PE export missing: {symbol}")


def _binding_address(workflow_data: JsonObject, intent_id: str) -> int:
    workflow = workflow_data.get("workflow")
    assert isinstance(workflow, dict)
    state = workflow.get("state")
    assert isinstance(state, dict)
    breakpoints = state.get("breakpoints")
    assert isinstance(breakpoints, dict)
    bindings = breakpoints.get("bindings")
    assert isinstance(bindings, list)
    for binding in bindings:
        if isinstance(binding, dict) and binding.get("intent_id") == intent_id:
            return int(binding["address"])
    raise AssertionError(f"workflow breakpoint binding missing: {intent_id}")


def _waited_state(data: JsonObject) -> JsonObject:
    state = data.get("state")
    assert isinstance(state, dict)
    return state


def _wait_for_gui(service: AnalysisService, session_id: str) -> None:
    deadline = time.time() + 30.0
    last_windows: JsonObject | None = None
    while time.time() < deadline:
        state = _ok(service.dynamic_state(session_id))
        if state.get("state") == "paused":
            _ok(service.dynamic_resume(session_id, timeout=15.0))
        last_windows = _ok(service.ui_windows_list(session_id))
        windows = last_windows.get("windows")
        assert isinstance(windows, list)
        if any(
            isinstance(window, dict)
            and window.get("class_name") == "HeadlessReFixtureWindow"
            for window in windows
        ):
            return
        time.sleep(0.2)
    raise AssertionError(f"gui fixture window not observed: {last_windows}")


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize("architecture", [Architecture.X64, Architecture.X86])
def test_m10_ui_drive_to_breakpoint_gate(architecture: Architecture) -> None:
    if os.name != "nt":
        pytest.skip("requires Windows")
    env_key = (
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    )
    os.environ[env_key] = str(_headless(architecture))
    gui = _gui(architecture)
    transform_rva = _export_rva(gui, "gui_fixture_transform")
    service = AnalysisService(Settings.load())
    session_id = _session_id(_ok(service.create_session(str(gui))))

    try:
        _ok(service.open_dynamic(session_id))
        _ok(service.dynamic_launch(session_id, timeout=60.0))
        _wait_for_gui(service, session_id)

        running = _ok(service.dynamic_wait(session_id, "running", timeout=15.0))
        assert _waited_state(running).get("state") == "running"
        paused = _ok(service.dynamic_pause(session_id, timeout=30.0))
        assert _waited_state(paused).get("state") == "paused"
        confirmed = _ok(service.dynamic_wait(session_id, "paused", timeout=15.0))
        assert _waited_state(confirmed).get("state") == "paused"

        _ok(
            service.workflow_module_track(
                session_id,
                _MODULE_KEY,
                ModuleSelector(path=str(gui.resolve())),
                timeout=30.0,
            )
        )
        breakpoint = _ok(
            service.workflow_breakpoint_put(
                session_id,
                _INTENT_ID,
                _MODULE_KEY,
                transform_rva,
                timeout=30.0,
            )
        )
        binding_address = _binding_address(breakpoint, _INTENT_ID)

        # Drive requires a live message pump; leave the paused setup state first.
        _ok(service.dynamic_resume(session_id, timeout=15.0))
        running_again = _ok(service.dynamic_wait(session_id, "running", timeout=15.0))
        assert _waited_state(running_again).get("state") == "running"

        driven = _ok(
            service.ui_drive_to_breakpoint(
                session_id,
                _INTENT_ID,
                accept_ui_goal=False,
                timeout=45.0,
                event_budget=4096,
                steps=[
                    {
                        "action": "resolve",
                        "class_name": "HeadlessReFixtureWindow",
                        "as_root": True,
                    },
                    {
                        "action": "resolve",
                        "parent_from": "root",
                        "class_name": "Button",
                        "title": "Transform",
                    },
                    {"action": "click", "timeout_ms": 10_000},
                ],
            )
        )

        matched = driven.get("matched_event")
        assert isinstance(matched, dict)
        assert matched.get("kind") == "breakpoint.hit"
        event_data = matched.get("data")
        assert isinstance(event_data, dict)
        assert event_data.get("intent_id") == _INTENT_ID
        assert event_data.get("address") == binding_address
        assert event_data.get("binding_address") == binding_address
        assert driven["ui_goal"] is False
        assert driven["stop_reason"] == "event"
        assert [step["action"] for step in driven["steps"]] == [
            "resolve",
            "resolve",
            "click",
        ]
    finally:
        service.close_session(session_id)
