"""Additional edge-path coverage for core/service_trace.py.

Complements test_trace_mixin_harness by driving the validation guards, the
disk/artifact-missing/quota-timeout arms, and the failure-recovery branches of
trace_start/stop/status that the happy-path harness tests do not reach. Reuses
the same fake-seam harness.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_trace_mixin_harness import (
    _err,
    _good_status,
    _make,
    _ok,
    _Runtime,
    _start,
    _state,
    _Worker,
)

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError

INVALID = "invalid_request"


# --- trace_start parameter validation ---


@pytest.mark.parametrize(
    ("kwargs", "path"),
    [
        ({}, ""),
        ({"max_events": 0}, "C:/x.trace"),
        ({"max_events": 2_000_000}, "C:/x.trace"),
        ({"timeout_ms": 0}, "C:/x.trace"),
        ({"timeout_ms": 4_000_000}, "C:/x.trace"),
        ({"max_file_bytes": 0}, "C:/x.trace"),
        ({"max_file_bytes": 512 * 1024 * 1024}, "C:/x.trace"),
    ],
)
def test_trace_start_rejects_out_of_range_parameters(
    tmp_path: Path, kwargs: dict[str, Any], path: str
) -> None:
    harness = _make(tmp_path, {"trace.start"})
    result = harness.trace_start("sess", path, **kwargs)
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_trace_start_refuses_when_disk_space_is_short(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _make(tmp_path, {"trace.start"})

    class _Usage:
        free = 0

    monkeypatch.setattr(
        "headless_re_mcp.core.service_trace.shutil.disk_usage", lambda _p: _Usage()
    )

    result = harness.trace_start("sess", "C:/x.trace", max_file_bytes=4096)

    assert result.ok is False and result.error is not None
    assert result.error.code == "insufficient_disk_space"
    assert result.error.details["available_disk_bytes"] == 0


def test_trace_start_flags_a_missing_artifact_file(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start(params: dict[str, Any]) -> dict[str, Any]:
        # Report a valid recording status but never create the artifact file.
        return {
            "recording": True,
            "path": params["path"],
            "max_events": params["max_events"],
            "timeout_ms": params["timeout_ms"],
            "max_file_bytes": params["max_file_bytes"],
            "events_written": 0,
            "file_bytes": 0,
            "elapsed_ms": 0,
            "stop_reason": "none",
        }

    worker.on("trace.start", start)
    worker.on("trace.stop", lambda _p: {"recording": False})

    result = harness.trace_start("sess", "C:/x.trace", max_file_bytes=4096)

    assert result.ok is False and result.error is not None
    assert result.error.code == "artifact_missing"


def test_trace_start_tears_down_when_a_safe_stop_is_impossible(tmp_path: Path) -> None:
    # No trace.stop capability, so the post-failure stop cannot be confirmed
    # safe and the analyzer must be failed.
    harness = _make(tmp_path, {"trace.start"})
    worker = harness._runtime_obj.worker

    def start(params: dict[str, Any]) -> dict[str, Any]:
        Path(params["path"]).write_bytes(b"partial")
        return {
            "recording": False,
            "path": params["path"],
            "max_events": params["max_events"],
            "timeout_ms": params["timeout_ms"],
            "max_file_bytes": params["max_file_bytes"],
            "events_written": 0,
            "file_bytes": 4,
            "elapsed_ms": 0,
            "stop_reason": "none",
        }

    worker.on("trace.start", start)

    result = harness.trace_start("sess", "C:/x.trace", max_file_bytes=4096)

    assert result.ok is False and result.error is not None
    assert result.error.code == "trace_start_failed"
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_start_wraps_an_unexpected_worker_error(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start(params: dict[str, Any]) -> dict[str, Any]:
        Path(params["path"]).write_bytes(b"partial")
        raise RuntimeError("native trace crash")

    worker.on("trace.start", start)
    worker.on("trace.stop", lambda _p: {"recording": False})

    result = harness.trace_start("sess", "C:/x.trace", max_file_bytes=4096)

    assert result.ok is False and result.error is not None
    assert "native trace crash" in result.error.message
    assert harness.failed and harness.failed[0][0] == "sess"


# --- trace_stop arms ---


def test_trace_stop_refuses_without_the_capability(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start"})
    assert _start(harness).ok is True

    result = harness.trace_stop("sess")

    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_stop_without_a_tracked_trace_returns_native(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.stop"})
    harness._runtime_obj.worker.on("trace.stop", lambda _p: {"stopped": True})

    result = harness.trace_stop("sess")

    assert result.ok is True and result.data is not None
    assert result.data["stopped"] is True


def test_trace_stop_when_the_runtime_is_unreachable(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.stop"})

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise XdbgRpcError("rpc_transport_error", "runtime gone")

    harness._runtime = _boom  # type: ignore[method-assign]

    result = harness.trace_stop("sess")

    assert result.ok is False and result.error is not None
    assert result.error.code == "rpc_transport_error"
    assert harness.failed == []  # runtime was None, nothing to tear down


def test_trace_stop_wraps_an_unexpected_worker_error(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    assert _start(harness).ok is True

    def _boom(_p: Any) -> Any:
        raise RuntimeError("stop crash")

    harness._runtime_obj.worker.on("trace.stop", _boom)

    result = harness.trace_stop("sess")

    assert result.ok is False and result.error is not None
    assert "stop crash" in result.error.message
    assert harness.failed and harness.failed[0][0] == "sess"
    state = harness._trace_owner.get("sess")
    assert state is not None and state.active is False


# --- trace_status arms ---


def test_trace_status_refuses_without_the_capability(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start"})
    assert _start(harness).ok is True

    result = harness.trace_status("sess")

    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_status_without_a_tracked_trace_returns_native(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.status"})
    harness._runtime_obj.worker.on("trace.status", lambda _p: {"recording": False})

    result = harness.trace_status("sess")

    assert result.ok is True and result.data is not None
    assert result.data["recording"] is False


def test_trace_status_reports_an_ongoing_trace_without_finalising(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    harness._runtime_obj.worker.on(
        "trace.status",
        lambda _p: _good_status(state, recording=True, events_written=1, file_bytes=8),
    )

    result = harness.trace_status("sess")

    assert result.ok is True and result.data is not None
    assert result.data["artifact_pending"] is True
    assert result.data["artifact_registered"] is False
    assert state.active is True


def test_trace_status_labels_a_timed_out_trace(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    # Force the elapsed clock past the deadline so the service stops it itself.
    state.started_monotonic = 0.0
    harness._runtime_obj.worker.on(
        "trace.status", lambda _p: _good_status(state, recording=True)
    )
    harness._runtime_obj.worker.on(
        "trace.stop",
        lambda _p: _good_status(state, recording=False, stop_reason="cancelled"),
    )

    result = harness.trace_status("sess")

    assert result.ok is True and result.data is not None
    assert result.data["stop_reason"] == "timeout"
    assert result.data["quota_stopped"] is True
    assert result.data["artifact_registered"] is True


def test_trace_status_error_while_recording_fails_the_runtime(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True

    def _boom(_p: Any) -> Any:
        raise XdbgRpcError("rpc_protocol_error", "worker went away")

    harness._runtime_obj.worker.on("trace.status", _boom)

    result = harness.trace_status("sess")

    assert result.ok is False and result.error is not None
    assert result.error.code == "rpc_protocol_error"
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_status_error_after_stop_finalises_the_partial(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    # A trace that has already ended (active False) but was never finalised: a
    # non-fatal status error should finalise the partial, not tear down.
    state.active = False

    def _boom(_p: Any) -> Any:
        raise XdbgRpcError("trace_status_hiccup", "transient")

    harness._runtime_obj.worker.on("trace.status", _boom)

    result = harness.trace_status("sess")

    assert result.ok is False and result.error is not None
    assert result.error.details["artifact_id"] == "artifact-1"
    assert harness.failed == []


def test_trace_status_unexpected_error_while_recording(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True

    def _boom(_p: Any) -> Any:
        raise RuntimeError("status crash")

    harness._runtime_obj.worker.on("trace.status", _boom)

    result = harness.trace_status("sess")

    assert result.ok is False and result.error is not None
    assert "status crash" in result.error.message
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_status_unexpected_error_after_finalize_replays_state(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    harness._runtime_obj.worker.on(
        "trace.stop",
        lambda _p: _good_status(state, recording=False, stop_reason="target_exited"),
    )
    assert harness.trace_stop("sess").ok is True

    def _boom(_p: Any) -> Any:
        raise RuntimeError("late status crash")

    harness._runtime_obj.worker.on("trace.status", _boom)

    result = harness.trace_status("sess")

    assert result.ok is True and result.data is not None
    assert result.data["artifact_id"] == "artifact-1"
    assert harness.failed == []


# --- _new_trace_artifact_path ---


def test_new_trace_artifact_path_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    with pytest.raises(ValueError, match="invalid session id"):
        harness._new_trace_artifact_path("../escape")


# --- _validate_trace_status detail arms ---


def test_validate_status_rejects_an_unparseable_path(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="invalid artifact path"):
        harness._validate_trace_status(
            state, _good_status(state, path="bad\x00path")
        )


def test_validate_status_rejects_a_mismatched_quota_field(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="invalid max_events"):
        harness._validate_trace_status(
            state, _good_status(state, max_events=state.max_events + 1)
        )


def test_validate_status_rejects_a_negative_counter(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="invalid events_written"):
        harness._validate_trace_status(state, _good_status(state, events_written=-1))


# --- _stop_trace_after_failure ---


def test_stop_after_failure_without_the_capability(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    runtime: Any = _Runtime(_Worker(set()))
    assert harness._stop_trace_after_failure(runtime, state) is False


def test_stop_after_failure_when_the_stop_is_not_confirmed(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    runtime: Any = _Runtime(_Worker({"trace.stop"}))
    runtime.worker.on("trace.stop", lambda _p: {"recording": True})
    assert harness._stop_trace_after_failure(runtime, state) is False


def test_stop_after_failure_swallows_a_worker_exception(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    runtime: Any = _Runtime(_Worker({"trace.stop"}))

    def _boom(_p: Any) -> Any:
        raise RuntimeError("stop threw")

    runtime.worker.on("trace.stop", _boom)
    assert harness._stop_trace_after_failure(runtime, state) is False


# --- _finalize_trace_artifact registration failure ---


def test_finalize_records_a_registration_failure(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    state.path.write_bytes(b"trace-bytes")

    def _boom(**_fields: Any) -> dict[str, Any]:
        raise KeyError("registration blew up")

    harness.record_artifact = _boom  # type: ignore[method-assign]

    harness._finalize_trace_artifact(state, terminal_reason="stopped")

    assert state.artifact_id is None
    assert state.artifact_error is not None
    assert "registration blew up" in state.artifact_error


# --- trace_api_arguments extra arms ---


def test_trace_api_arguments_rejects_a_non_integer_resolution(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    harness.stub_symbols = lambda s, e: _ok({"symbol": e})  # resolution has no address
    result = harness.trace_api_arguments("sess", "kernel32!Foo")
    assert result.ok is False and result.error is not None
    assert result.error.code == INVALID


def test_trace_api_arguments_stops_when_resume_fails(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    target = 0x17000
    harness.stub_bp_set = lambda s, a: _ok({"set": a})
    harness.stub_resume = lambda s: _err("resume_failed")

    result = harness.trace_api_arguments("sess", address=target, max_hits=3)

    assert result.ok is True and result.data is not None
    assert result.data["hit_count"] == 0
    assert result.data["stopped_elsewhere"] is False
    assert harness.bp_removed == [target]
