"""TraceMixin edge arcs: input validation, quota timeout, and failure handlers.

The core harness (``test_trace_mixin_harness``) drives the load-bearing
start/stop/status/finalise flow. These pin the guards around it that only fire
on a bad input, a starved disk, a backend that answers wrong, or a worker that
dies at an awkward moment: every ``trace_start`` range check, the disk-quota
refusal, the missing-artifact and capability guards, the service-side timeout
stop, the stale-poll replay on a generic error, the artifact-registration
failure, and the ``_stop_trace_after_failure`` fallbacks that decide whether
the analyzer must be torn down. Each is a caller-visible contract: a trace that
kept running past its budget, or a lost trace that never got finalised as a
partial, would be a silent regression.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from time import monotonic
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_trace as service_trace
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Architecture
from tests.unit.test_trace_mixin_harness import (
    _err,
    _good_status,
    _good_status_from_params,
    _make,
    _ok,
    _start,
    _state,
)

INVALID = "invalid_request"


# ---------------------------------------------------------------------------
# trace_start input validation.


@pytest.mark.parametrize(
    ("kwargs", "path"),
    [
        ({}, ""),  # empty path
        ({"max_events": 0}, "C:/t.trace"),
        ({"max_events": 2_000_000}, "C:/t.trace"),
        ({"timeout_ms": 0}, "C:/t.trace"),
        ({"timeout_ms": 4_000_000}, "C:/t.trace"),
        ({"max_file_bytes": 0}, "C:/t.trace"),
        ({"max_file_bytes": 512 * 1024 * 1024}, "C:/t.trace"),
    ],
)
def test_trace_start_rejects_out_of_range_inputs(
    tmp_path: Path, kwargs: dict[str, Any], path: str
) -> None:
    harness = _make(tmp_path, {"trace.start"})
    result = harness.trace_start("sess", path, **kwargs)
    assert result.ok is False
    assert result.error is not None and result.error.code == "invalid_params"


def test_trace_start_refuses_when_the_disk_cannot_hold_the_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _make(tmp_path, {"trace.start"})

    def tiny_disk(_path: Any) -> SimpleNamespace:
        return SimpleNamespace(total=100, used=90, free=10)

    monkeypatch.setattr(shutil, "disk_usage", tiny_disk)
    result = harness.trace_start("sess", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert result.error.code == "insufficient_disk_space"
    assert harness.failed == []  # nothing to tear down; state was never registered


def test_trace_start_flags_a_backend_that_never_wrote_the_artifact(tmp_path: Path) -> None:
    """trace.start claiming success without creating the file is a protocol failure."""
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start_without_file(params: dict[str, Any]) -> dict[str, Any]:
        return _good_status_from_params(params, recording=True)

    worker.on("trace.start", start_without_file)
    worker.on("trace.stop", lambda _p: {"recording": False})
    result = harness.trace_start("sess", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert result.error.code == "artifact_missing"


def test_trace_start_tears_down_when_the_safe_stop_has_no_capability(tmp_path: Path) -> None:
    """A start failure with no trace.stop cannot stop safely, so the runtime fails."""
    harness = _make(tmp_path, {"trace.start"})  # no trace.stop
    worker = harness._runtime_obj.worker

    def start_not_recording(params: dict[str, Any]) -> dict[str, Any]:
        Path(params["path"]).write_bytes(b"partial")
        return _good_status_from_params(params, recording=False)

    worker.on("trace.start", start_not_recording)
    result = harness.trace_start("sess", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert result.error.code == "trace_start_failed"
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_start_tears_down_when_the_safe_stop_still_records(tmp_path: Path) -> None:
    """A stop that reports still-recording is unsafe, so the runtime is failed."""
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start_not_recording(params: dict[str, Any]) -> dict[str, Any]:
        Path(params["path"]).write_bytes(b"partial")
        return _good_status_from_params(params, recording=False)

    worker.on("trace.start", start_not_recording)
    worker.on("trace.stop", lambda _p: {"recording": True})  # never leaves recording
    result = harness.trace_start("sess", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_start_tears_down_when_the_safe_stop_raises(tmp_path: Path) -> None:
    """A stop that raises leaves the trace state uncertain, so the runtime is failed."""
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start_not_recording(params: dict[str, Any]) -> dict[str, Any]:
        Path(params["path"]).write_bytes(b"partial")
        return _good_status_from_params(params, recording=False)

    def stop_boom(_p: Any) -> dict[str, Any]:
        raise RuntimeError("stop transport died")

    worker.on("trace.start", start_not_recording)
    worker.on("trace.stop", stop_boom)
    result = harness.trace_start("sess", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_start_wraps_a_failure_before_the_trace_is_registered(tmp_path: Path) -> None:
    """A generic error before registration has nothing to finalise or tear down."""
    harness = _make(tmp_path, {"trace.start"})
    # A traversing session id fails inside _new_trace_artifact_path, before the
    # runtime is resolved or the trace state is registered.
    result = harness.trace_start("../evil", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert harness.failed == []


def test_trace_start_wraps_a_non_rpc_failure_and_finalises(tmp_path: Path) -> None:
    """A generic error after the trace is registered still finalises and tears down."""
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start_boom(_p: Any) -> dict[str, Any]:
        raise RuntimeError("worker vanished mid-start")

    worker.on("trace.start", start_boom)
    worker.on("trace.stop", lambda _p: {"recording": False})
    result = harness.trace_start("sess", "C:/t.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert harness.failed and harness.failed[0][0] == "sess"


# ---------------------------------------------------------------------------
# trace_stop guards.


def test_trace_stop_refuses_a_backend_without_the_capability(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start"})  # no trace.stop
    assert _start(harness).ok is True
    result = harness.trace_stop("sess")
    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_stop_without_an_active_trace_returns_the_native_reply(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.stop"})  # nothing started
    harness._runtime_obj.worker.on("trace.stop", lambda _p: {"recording": False, "note": "idle"})
    result = harness.trace_stop("sess")
    assert result.ok is True and result.data is not None
    assert result.data["note"] == "idle"


def test_trace_stop_tolerates_a_runtime_lookup_failure(tmp_path: Path) -> None:
    """An RPC error resolving the runtime leaves nothing to finalise or tear down."""
    harness = _make(tmp_path, {"trace.stop"})

    def no_runtime(*_args: Any, **_kwargs: Any) -> Any:
        raise XdbgRpcError("rpc_transport_error", "cannot reach worker")

    harness._runtime = no_runtime  # type: ignore[method-assign]
    result = harness.trace_stop("sess")
    assert result.ok is False and result.error is not None
    assert result.error.code == "rpc_transport_error"
    assert harness.failed == []  # runtime was never resolved


def test_trace_stop_generic_failure_before_runtime_is_a_clean_no_op(tmp_path: Path) -> None:
    """A generic runtime-lookup failure leaves nothing to finalise or tear down."""
    harness = _make(tmp_path, {"trace.stop"})

    def no_runtime(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("cannot reach worker")

    harness._runtime = no_runtime  # type: ignore[method-assign]
    result = harness.trace_stop("sess")
    assert result.ok is False and result.error is not None
    assert harness.failed == []


def test_trace_stop_wraps_a_non_rpc_failure_and_finalises(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None

    def stop_boom(_p: Any) -> dict[str, Any]:
        raise RuntimeError("stop transport died")

    harness._runtime_obj.worker.on("trace.stop", stop_boom)
    result = harness.trace_stop("sess")
    assert result.ok is False and result.error is not None
    assert state.active is False
    assert harness.failed and harness.failed[0][0] == "sess"


# ---------------------------------------------------------------------------
# trace_status guards and quota timeout.


def test_trace_status_refuses_a_backend_without_the_capability(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start"})  # no trace.status
    assert _start(harness).ok is True
    result = harness.trace_status("sess")
    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_status_without_an_active_trace_returns_the_native_reply(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.status"})
    harness._runtime_obj.worker.on(
        "trace.status", lambda _p: {"recording": False, "note": "no trace"}
    )
    result = harness.trace_status("sess")
    assert result.ok is True and result.data is not None
    assert result.data["note"] == "no trace"


def test_trace_status_reports_an_active_trace_that_is_under_budget(tmp_path: Path) -> None:
    """A recording trace still under every quota is reported without a stop."""
    harness = _make(tmp_path, {"trace.start", "trace.status", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    harness._runtime_obj.worker.on(
        "trace.status", lambda _p: _good_status(state, recording=True, events_written=5)
    )
    result = harness.trace_status("sess")
    assert result.ok is True and result.data is not None
    assert result.data["artifact_pending"] is True
    assert result.data["artifact_registered"] is False
    methods = [name for name, _p, _t in harness._runtime_obj.worker.calls]
    assert methods.count("trace.stop") == 0  # under budget: no service-side stop


def test_trace_status_stops_and_labels_a_timed_out_trace(tmp_path: Path) -> None:
    """A trace past its time budget is stopped and its reason relabelled timeout."""
    harness = _make(tmp_path, {"trace.start", "trace.status", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    # Backdate the start so the elapsed clock is already past the deadline.
    state.started_monotonic = monotonic() - 10_000.0
    harness._runtime_obj.worker.on(
        "trace.status", lambda _p: _good_status(state, recording=True, events_written=1)
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


def test_trace_status_rpc_error_on_an_active_trace_tears_down(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True

    def boom(_p: Any) -> dict[str, Any]:
        raise XdbgRpcError("rpc_transport_error", "worker went away")

    harness._runtime_obj.worker.on("trace.status", boom)
    result = harness.trace_status("sess")
    assert result.ok is False and result.error is not None
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_status_rpc_error_on_an_inactive_unfinalised_trace_finalises(
    tmp_path: Path,
) -> None:
    """An inactive, never-registered trace hitting an RPC error is finalised, not replayed."""
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    state.active = False  # inactive but artifact_id still None

    def boom(_p: Any) -> dict[str, Any]:
        raise XdbgRpcError("backend_busy", "transient status hiccup")  # non-fatal code

    harness._runtime_obj.worker.on("trace.status", boom)
    result = harness.trace_status("sess")
    assert result.ok is False and result.error is not None
    assert state.artifact_id == "artifact-1"  # finalised on the way out
    assert harness.failed == []  # not active and not fatal: no teardown


def test_trace_status_generic_error_replays_a_finalised_trace(tmp_path: Path) -> None:
    """A stale poll hitting a generic error replays the finalised state."""
    harness = _make(tmp_path, {"trace.start", "trace.stop", "trace.status"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    harness._runtime_obj.worker.on(
        "trace.stop",
        lambda _p: _good_status(state, recording=False, stop_reason="target_exited"),
    )
    assert harness.trace_stop("sess").ok is True  # artifact_id set, active False

    def boom(_p: Any) -> dict[str, Any]:
        raise RuntimeError("worker gone")

    harness._runtime_obj.worker.on("trace.status", boom)
    result = harness.trace_status("sess")
    assert result.ok is True and result.data is not None
    assert result.data["artifact_id"] == "artifact-1"
    assert harness.failed == []


def test_trace_status_generic_failure_before_runtime_is_a_clean_no_op(tmp_path: Path) -> None:
    """A generic runtime-lookup failure leaves nothing to replay, finalise, or fail."""
    harness = _make(tmp_path, {"trace.status"})

    def no_runtime(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("cannot reach worker")

    harness._runtime = no_runtime  # type: ignore[method-assign]
    result = harness.trace_status("sess")
    assert result.ok is False and result.error is not None
    assert harness.failed == []


def test_trace_status_generic_error_on_an_active_trace_tears_down(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status"})
    assert _start(harness).ok is True

    def boom(_p: Any) -> dict[str, Any]:
        raise RuntimeError("worker gone")

    harness._runtime_obj.worker.on("trace.status", boom)
    result = harness.trace_status("sess")
    assert result.ok is False and result.error is not None
    assert harness.failed and harness.failed[0][0] == "sess"


# ---------------------------------------------------------------------------
# Path and validation helpers.


def test_new_trace_artifact_path_rejects_a_traversing_session_id(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    with pytest.raises(ValueError, match="invalid session id"):
        harness._new_trace_artifact_path("../evil")


def test_new_trace_artifact_path_rejects_an_escaping_artifact_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A generated name that would leave the session directory is refused."""
    harness = _make(tmp_path, set())
    monkeypatch.setattr(service_trace, "uuid4", lambda: SimpleNamespace(hex="sub/evil"))
    with pytest.raises(ValueError, match="escaped the session artifact directory"):
        harness._new_trace_artifact_path("sess")


def test_validate_status_rejects_an_unparseable_path(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="invalid artifact path"):
        harness._validate_trace_status(state, _good_status(state, path="bad\x00path"))


def test_validate_status_rejects_a_mismatched_quota_field(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="invalid max_events"):
        harness._validate_trace_status(state, _good_status(state, max_events=state.max_events + 7))


def test_validate_status_rejects_a_negative_counter(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="invalid events_written"):
        harness._validate_trace_status(state, _good_status(state, events_written=-5))


def test_finalize_discloses_a_failed_artifact_registration(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    state.path.write_bytes(b"trace-bytes")

    def boom_register(**_fields: Any) -> dict[str, Any]:
        raise ValueError("artifact registry unavailable")

    harness.record_artifact = boom_register  # type: ignore[method-assign]
    harness._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id is None
    assert "artifact registry unavailable" in (state.artifact_error or "")


# ---------------------------------------------------------------------------
# trace_api_arguments guards.


def test_trace_api_arguments_rejects_a_resolution_without_an_address(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    harness.stub_symbols = lambda s, e: _ok({"symbol": e})  # no address key
    result = harness.trace_api_arguments("sess", "kernel32!CreateFileW")
    assert result.ok is False and result.error is not None
    assert result.error.code == INVALID
    assert harness.bp_removed == []  # never armed


def test_trace_api_arguments_stops_when_a_resume_fails(tmp_path: Path) -> None:
    harness = _make(tmp_path, set(), Architecture.X64)
    target = 0x17000
    harness.stub_bp_set = lambda s, a: _ok({"set": a})
    harness.stub_resume = lambda s: _err("resume_failed")
    result = harness.trace_api_arguments("sess", address=target, max_hits=3)
    assert result.ok is True and result.data is not None
    assert result.data["hit_count"] == 0
    assert result.data["stopped_elsewhere"] is False
    assert harness.bp_removed == [target]  # still removed after the loop
