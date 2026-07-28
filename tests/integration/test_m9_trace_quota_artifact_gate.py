"""M9 Gate: trace quota truncation/cancel and session-owned artifact registration."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, Result
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
def test_m9_trace_quota_cancel_and_artifact_gate(architecture: Architecture) -> None:
    if os.name != "nt":
        pytest.skip("requires Windows")
    os.environ[
        "HEADLESS_RE_X64DBG_HEADLESS_X64"
        if architecture is Architecture.X64
        else "HEADLESS_RE_X64DBG_HEADLESS_X86"
    ] = str(_headless(architecture))

    settings = Settings.load()
    service = AnalysisService(settings)
    session_id = _sid(_ok(service.create_session(str(_fixture(architecture)))))
    try:
        _ok(service.open_dynamic(session_id))
        _ok(service.dynamic_launch(session_id, arguments="--debug-wait", timeout=60.0))
        _ok(service.dynamic_wait(session_id, "paused", timeout=30.0))

        # A2/A3: tiny max_events + short timeout; artifact must be session-owned.
        started = _ok(
            service.trace_start(
                session_id,
                path=str(Path("C:/ignored-caller-path.trace")),
                max_events=1,
                timeout_ms=1_500,
                max_file_bytes=64 * 1024,
                timeout=30.0,
            )
        )
        assert started.get("recording") is True
        assert started.get("session_owned") is True
        artifact_path = Path(str(started["artifact_path"]))
        assert artifact_path.parent == (settings.artifact_root.resolve() / "trace" / session_id)
        assert artifact_path.is_file()

        _ok(service.dynamic_resume(session_id, timeout=15.0))
        # Let the runner produce at least one trace event / hit timeout quota.
        deadline = time.time() + 10.0
        idle: JsonObject | None = None
        while time.time() < deadline:
            status = _ok(service.trace_status(session_id, timeout=10.0))
            if status.get("recording") is False:
                idle = status
                break
            time.sleep(0.2)
        if idle is None:
            idle = _ok(service.trace_stop(session_id, timeout=30.0))

        assert idle.get("recording") is False
        assert idle.get("artifact_registered") is True
        assert isinstance(idle.get("artifact_id"), str) and idle["artifact_id"]
        assert Path(str(idle["artifact_path"])).is_file()
        reason = str(idle.get("stop_reason") or idle.get("terminal_reason") or "")
        assert reason, idle

        # Cancel path on a fresh recording.
        _ok(service.dynamic_wait(session_id, "paused", timeout=15.0))
        again = _ok(
            service.trace_start(
                session_id,
                path=str(Path("C:/ignored-cancel.trace")),
                max_events=10_000,
                timeout_ms=60_000,
                max_file_bytes=1024 * 1024,
                timeout=30.0,
            )
        )
        assert again.get("recording") is True
        cancelled = _ok(service.trace_stop(session_id, timeout=30.0))
        assert cancelled.get("recording") is False
        assert cancelled.get("artifact_registered") is True
        assert Path(str(cancelled["artifact_path"])).is_file()
        assert cancelled.get("artifact_id") != idle.get("artifact_id")
    finally:
        service.close_session(session_id)
