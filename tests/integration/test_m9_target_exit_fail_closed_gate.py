"""M9 Gate: fail-closed behaviour when the debuggee exits mid-flight."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


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


def _fixture(architecture: Architecture) -> Path:
    path = (
        _PROJECT_ROOT
        / "artifacts"
        / f"fixtures-{architecture.value}"
        / "headless_fixture.exe"
    )
    if path.is_file():
        return path
    pytest.skip(f"fixture missing: {path}")


def _ok(result: Result[JsonObject]) -> JsonObject:
    assert result.ok is True, result.error
    assert isinstance(result.data, dict)
    return result.data


def _sid(data: JsonObject) -> str:
    session = data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.parametrize("architecture", [Architecture.X64, Architecture.X86])
def test_m9_target_exit_fail_closed_gate(architecture: Architecture) -> None:
    if os.name != "nt":
        pytest.skip("requires Windows")
    os.environ[
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    ] = str(_headless(architecture))

    service = AnalysisService(Settings.load())
    fixture = _fixture(architecture)
    session_id = _sid(_ok(service.create_session(str(fixture))))
    try:
        _ok(service.open_dynamic(session_id))
        _ok(service.dynamic_launch(session_id, timeout=60.0))
        _ok(service.dynamic_wait(session_id, "paused", timeout=30.0))
        _ok(
            service.workflow_module_track(
                session_id,
                "main",
                ModuleSelector(path=str(fixture.resolve())),
                timeout=30.0,
            )
        )

        # Target exit while workflow is armed must fail closed, not hang.
        stopped = service.dynamic_stop(session_id, timeout=30.0)
        assert stopped.ok is True, stopped.error

        later = service.dynamic_registers_read(session_id)
        assert later.ok is False
        assert later.error is not None
        assert later.error.code in {
            "not_debugging",
            "invalid_state",
            "backend_error",
            "rpc_transport_error",
            "not_paused",
        }

        wf = service.workflow_breakpoint_list(session_id)
        # Either still readable with empty bindings or structured failure — never crash.
        assert wf.ok is True or (wf.error is not None and wf.error.code)

        state = service.dynamic_state(session_id)
        if state.ok and state.data:
            windows = state.data.get("analyzer_windows")
            assert windows in (None, [], ())
    finally:
        service.close_session(session_id)