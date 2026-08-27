"""Bounded x64dbg tracing must finalise an artifact even when a trace goes wrong.

``TraceMixin`` is the one debugger surface that writes an unbounded amount of
data, so every entry point carries an event/byte/time budget, validates the
native status envelope against the session-owned artifact, and finalises (or
truncates) the file on any exit -- a partial trace with a stop reason is useful,
a leaked one is not. These tests drive the real ``AnalysisService`` with a fake
x64dbg worker (extending the shared ``FakeDynamicWorker``) so the whole
start/status/stop lifecycle, the ``_validate_trace_status`` guards, and the
Microsoft-x64 / x86-stack argument decoders are exercised without a Windows
debugger.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_trace import (
    TraceMixin,
    _instruction_pointer,
    _register_arguments,
    _stack_arguments,
    _TraceArtifactState,
)
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]

_TRACE_CAPS = frozenset(
    {"trace.start", "trace.stop", "trace.status", "stack.read", "symbols.resolve"}
)


class FakeTraceWorker(FakeDynamicWorker):
    """A dynamic worker that also serves the trace.* / stack / symbol surface."""

    def __init__(
        self,
        *,
        architecture: str = "x64",
        extra_caps: frozenset[str] = _TRACE_CAPS,
        drop_caps: frozenset[str] = frozenset(),
        **kwargs: Any,
    ) -> None:
        super().__init__(architecture=architecture, **kwargs)
        self._extra_caps = extra_caps
        self._drop_caps = drop_caps
        self.trace_path: str | None = None
        self.trace_quota: JsonObject = {}
        self.recording = False
        self.stop_reason = "none"
        self.events_written = 0
        self.trace_file_bytes = 16
        self.write_trace_file = True
        self.delete_on_stop = False
        self.stop_keeps_recording = False
        self.command_errors: dict[str, BaseException] = {}
        self.symbol_address: int | None = 0x140001000

    @property
    def capabilities(self) -> frozenset[str]:
        caps = set(super().capabilities)
        caps |= self._extra_caps
        caps -= self._drop_caps
        return frozenset(caps)

    def _trace_status_payload(self) -> JsonObject:
        path = self.trace_path or ""
        on_disk = Path(path)
        size = on_disk.stat().st_size if path and on_disk.is_file() else self.trace_file_bytes
        return {
            "recording": self.recording,
            "path": path,
            **self.trace_quota,
            "events_written": self.events_written,
            "file_bytes": size,
            "elapsed_ms": 0,
            "stop_reason": self.stop_reason,
        }

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        values = params or {}
        err = self.command_errors.get(command)
        if err is not None:
            self.requests.append((command, dict(values)))
            raise err
        if command == "trace.start":
            self.requests.append((command, dict(values)))
            self.trace_path = str(values["path"])
            self.trace_quota = {
                "max_events": values["max_events"],
                "timeout_ms": values["timeout_ms"],
                "max_file_bytes": values["max_file_bytes"],
            }
            self.recording = True
            self.stop_reason = "none"
            if self.write_trace_file:
                out = Path(self.trace_path)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(b"\x00" * max(1, self.trace_file_bytes))
            return self._trace_status_payload()
        if command == "trace.stop":
            self.requests.append((command, dict(values)))
            if not self.stop_keeps_recording:
                self.recording = False
                if self.stop_reason in {"none", ""}:
                    self.stop_reason = "stopped"
            if self.delete_on_stop and self.trace_path:
                Path(self.trace_path).unlink(missing_ok=True)
            return self._trace_status_payload()
        if command == "trace.status":
            self.requests.append((command, dict(values)))
            return self._trace_status_payload()
        if command == "stack.read":
            self.requests.append((command, dict(values)))
            count = int(values.get("count", 1))
            return {
                "entries": [{"value": 0xAAAA0000 + index} for index in range(count)],
                "pointer_size": 4,
            }
        if command == "symbols.resolve":
            self.requests.append((command, dict(values)))
            return {"address": self.symbol_address, "expression": values.get("expression")}
        return super().request(command, params, timeout=timeout)


@pytest.fixture
def trace_env(tmp_path: Path) -> Iterator[tuple[AnalysisService, str, FakeTraceWorker]]:
    worker = FakeTraceWorker()
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    try:
        yield service, session_id, worker
    finally:
        service.close_all()


def _launch(
    tmp_path: Path, worker: FakeTraceWorker, *, machine: int = 0x8664
) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, machine=machine)
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    assert service.dynamic_launch(session_id).ok
    return service, session_id


# --------------------------------------------------------------------------
# pure argument decoders
# --------------------------------------------------------------------------


def test_register_arguments_reads_the_microsoft_x64_bank() -> None:
    registers = {"registers": {"rcx": 1, "rdx": 2, "r8": True, "r9": 4}}
    decoded = _register_arguments(registers, 4)
    assert [item["source"] for item in decoded] == ["rcx", "rdx", "r8", "r9"]
    assert decoded[0]["value"] == 1
    # A bool is not accepted as an integer argument value.
    assert decoded[2]["value"] is None


def test_register_arguments_rejects_bad_input() -> None:
    assert _register_arguments(None, 4) == []
    assert _register_arguments({"rcx": 1}, 0) == []


def test_stack_arguments_reads_above_the_return_address() -> None:
    payload = {
        "pointer_size": 8,
        "entries": [
            {"value": 0xDEAD},  # return address slot
            {"value": 10},
            {"value": 20},
        ],
    }
    decoded = _stack_arguments(payload, 2)
    assert decoded[0]["value"] == 10
    assert decoded[1]["value"] == 20
    assert decoded[0]["source"] == "[esp+0x8]"


def test_stack_arguments_handles_missing_and_bad_input() -> None:
    assert _stack_arguments(None, 2) == []
    assert _stack_arguments({"entries": "no"}, 2) == []
    short = _stack_arguments({"entries": [{"value": 1}]}, 2)
    assert short[0]["value"] is None and short[1]["value"] is None


def test_instruction_pointer_prefers_known_names() -> None:
    assert _instruction_pointer({"registers": {"rip": 0x1000}}) == 0x1000
    assert _instruction_pointer({"eip": 0x2000}) == 0x2000
    assert _instruction_pointer({"pc": True}) is None
    assert _instruction_pointer(None) is None
    assert _instruction_pointer({"rax": 5}) is None


# --------------------------------------------------------------------------
# _validate_trace_status guards (called directly; self is unused)
# --------------------------------------------------------------------------


def _valid_state_and_payload(tmp_path: Path) -> tuple[_TraceArtifactState, JsonObject]:
    path = (tmp_path / "run.trace64").resolve()
    state = _TraceArtifactState(
        session_id="s",
        path=path,
        requested_path="C:/caller.trace",
        max_events=100,
        timeout_ms=1000,
        max_file_bytes=65536,
        started_monotonic=0.0,
    )
    payload = {
        "recording": True,
        "path": str(path),
        "max_events": 100,
        "timeout_ms": 1000,
        "max_file_bytes": 65536,
        "events_written": 0,
        "file_bytes": 0,
        "elapsed_ms": 0,
        "stop_reason": "none",
    }
    return state, payload


def _validate(state: _TraceArtifactState, payload: Any, **kwargs: Any) -> JsonObject:
    # _validate_trace_status never touches self, so a bare stand-in is enough.
    return TraceMixin._validate_trace_status(cast(TraceMixin, object()), state, payload, **kwargs)


def test_validate_rejects_a_non_object(tmp_path: Path) -> None:
    state, _ = _valid_state_and_payload(tmp_path)
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, ["not", "a", "dict"])
    assert exc.value.code == "rpc_protocol_error"


def test_validate_requires_a_boolean_recording(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["recording"] = 1
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload)
    assert exc.value.code == "rpc_protocol_error"


def test_validate_enforces_require_recording_true(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["recording"] = False
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload, require_recording=True)
    assert exc.value.code == "trace_start_failed"


def test_validate_enforces_require_recording_false(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["recording"] = True
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload, require_recording=False)
    assert exc.value.code == "trace_stop_failed"


def test_validate_rejects_a_foreign_artifact_path(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["path"] = str((tmp_path / "somewhere-else.trace").resolve())
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload)
    assert exc.value.code == "rpc_protocol_error"


def test_validate_rejects_a_mismatched_quota(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["max_events"] = 999
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload)
    assert exc.value.code == "rpc_protocol_error"


def test_validate_backfills_missing_quota_and_counters(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    del payload["max_events"]
    del payload["events_written"]
    payload["stop_reason"] = 123
    data = _validate(state, payload)
    assert data["max_events"] == 100
    assert data["events_written"] == 0
    assert data["stop_reason"] == "none"


def test_validate_rejects_a_negative_counter(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["events_written"] = -1
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload)
    assert exc.value.code == "rpc_protocol_error"


def test_validate_rejects_an_over_quota_artifact(tmp_path: Path) -> None:
    state, payload = _valid_state_and_payload(tmp_path)
    payload["events_written"] = 200
    with pytest.raises(XdbgRpcError) as exc:
        _validate(state, payload)
    assert exc.value.code == "trace_quota_violation"


# --------------------------------------------------------------------------
# trace_start
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"path": ""},
        {"max_events": 0},
        {"max_events": 2_000_000},
        {"timeout_ms": 0},
        {"timeout_ms": 5_000_000},
        {"max_file_bytes": 0},
        {"max_file_bytes": 512 * 1024 * 1024},
    ],
)
def test_trace_start_rejects_out_of_range_arguments(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker], kwargs: JsonObject
) -> None:
    service, session_id, _ = trace_env
    call: JsonObject = {"path": "C:/c.trace"}
    call.update(kwargs)
    result = service.trace_start(session_id, **call)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_trace_start_records_a_bounded_trace(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    result = service.trace_start(
        session_id, "C:/caller.trace", max_events=100, timeout_ms=1000, max_file_bytes=65536
    )
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["recording"] is True
    assert result.data["requested_path"] == "C:/caller.trace"
    assert result.data["session_owned"] is True
    assert result.data["artifact_path"].endswith(".trace64")


def test_trace_start_refuses_when_disk_is_too_small(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker], monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _ = trace_env

    class _Usage:
        free = 8

    monkeypatch.setattr(
        "headless_re_mcp.core.service_trace.shutil.disk_usage", lambda _p: _Usage()
    )
    result = service.trace_start(session_id, "C:/c.trace", max_file_bytes=65536)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "insufficient_disk_space"
    assert result.error.retryable is True


def test_trace_start_refuses_when_capability_is_missing(tmp_path: Path) -> None:
    worker = FakeTraceWorker(drop_caps=frozenset({"trace.start"}))
    service, session_id = _launch(tmp_path, worker)
    try:
        result = service.trace_start(session_id, "C:/c.trace")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_trace_start_refuses_a_second_active_trace(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    assert service.trace_start(session_id, "C:/c.trace").ok
    second = service.trace_start(session_id, "C:/c2.trace")
    assert second.ok is False
    assert second.error is not None
    assert second.error.code == "already_tracing"


def test_trace_start_detects_a_missing_artifact(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    worker.write_trace_file = False
    service, session_id = _launch(tmp_path, worker)
    try:
        result = service.trace_start(session_id, "C:/c.trace")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "artifact_missing"
    finally:
        service.close_all()


def test_trace_start_detects_a_worker_that_never_records(tmp_path: Path) -> None:
    worker = FakeTraceWorker()

    def _no_record(
        command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> Any:
        if command == "trace.start":
            worker.requests.append((command, dict(params or {})))
            path = str((params or {})["path"])
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"\x00" * 8)
            return {
                "recording": False,
                "path": path,
                "max_events": (params or {})["max_events"],
                "timeout_ms": (params or {})["timeout_ms"],
                "max_file_bytes": (params or {})["max_file_bytes"],
                "events_written": 0,
                "file_bytes": 8,
                "elapsed_ms": 0,
                "stop_reason": "none",
            }
        return FakeTraceWorker.request(worker, command, params, timeout=timeout)

    service, session_id = _launch(tmp_path, worker)
    monkey = worker
    monkey.request = _no_record  # type: ignore[method-assign]
    try:
        result = service.trace_start(session_id, "C:/c.trace")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "trace_start_failed"
    finally:
        service.close_all()


def test_trace_start_maps_an_unexpected_exception(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    worker.command_errors["trace.start"] = RuntimeError("worker crashed")
    service, session_id = _launch(tmp_path, worker)
    try:
        result = service.trace_start(session_id, "C:/c.trace")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


@pytest.mark.parametrize(
    "configure",
    [
        pytest.param(lambda w: w.__setattr__("_drop_caps", frozenset({"trace.stop"}))),
        pytest.param(lambda w: w.__setattr__("stop_keeps_recording", True)),
        pytest.param(
            lambda w: w.command_errors.__setitem__("trace.stop", RuntimeError("stop crashed"))
        ),
    ],
)
def test_trace_start_fails_the_runtime_when_cleanup_stop_is_unsafe(
    tmp_path: Path, configure: Any
) -> None:
    """An artifact-missing start whose safety stop cannot be trusted fails the runtime."""
    worker = FakeTraceWorker()
    worker.write_trace_file = False
    configure(worker)
    service, session_id = _launch(tmp_path, worker)
    try:
        result = service.trace_start(session_id, "C:/c.trace")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "artifact_missing"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# trace_stop
# --------------------------------------------------------------------------


def test_trace_stop_finalises_the_artifact(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    assert service.trace_start(session_id, "C:/c.trace").ok
    result = service.trace_stop(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_registered"] is True
    assert result.data["artifact_id"]


def test_trace_stop_without_an_active_trace_passes_through(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    result = service.trace_stop(session_id)
    assert result.ok, result.error


def test_trace_stop_refuses_when_capability_is_missing(tmp_path: Path) -> None:
    worker = FakeTraceWorker(drop_caps=frozenset({"trace.stop"}))
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        result = service.trace_stop(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_trace_stop_fails_when_recording_never_stops(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    worker.stop_keeps_recording = True
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        result = service.trace_stop(session_id)
        assert result.ok is False
        assert result.error is not None
        # The bounded partial file is still finalised and its id attached.
        assert result.error.details.get("artifact_id")
    finally:
        service.close_all()


def test_trace_stop_finalises_a_missing_file_with_an_error(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    worker.delete_on_stop = True
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        result = service.trace_stop(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["artifact_registered"] is False
        assert result.data["artifact_error"]
    finally:
        service.close_all()


def test_trace_stop_maps_an_unexpected_exception(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        worker.command_errors["trace.stop"] = RuntimeError("stop crashed")
        result = service.trace_stop(session_id)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_trace_stop_truncates_and_registers_an_over_quota_partial(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace", max_file_bytes=1024).ok
        # A writer that overruns its byte quota leaves an oversized file behind;
        # stop must truncate it to the cap and register it as a partial trace.
        assert worker.trace_path is not None
        Path(worker.trace_path).write_bytes(b"\x00" * 4096)
        result = service.trace_stop(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "trace_quota_violation"
        state = service._trace_owner.get(session_id)
        assert state is not None
        assert state.artifact_truncated is True
        assert state.artifact_size == 1024
    finally:
        service.close_all()


def test_trace_stop_records_a_finalize_error(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok

        def _boom(**fields: Any) -> JsonObject:
            raise ValueError("repository refused the artifact")

        service.record_artifact = _boom  # type: ignore[method-assign]
        result = service.trace_stop(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["artifact_registered"] is False
        assert "repository refused" in str(result.data["artifact_error"])
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# trace_status
# --------------------------------------------------------------------------


def test_trace_status_reports_a_live_trace(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    assert service.trace_start(session_id, "C:/c.trace").ok
    result = service.trace_status(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["recording"] is True
    assert result.data["artifact_pending"] is True


def test_trace_status_finalises_once_recording_stops(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        worker.recording = False
        worker.stop_reason = "stopped"
        result = service.trace_status(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["recording"] is False
        assert result.data["artifact_registered"] is True
    finally:
        service.close_all()


def test_trace_status_enforces_quota_with_a_service_side_stop(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(
            session_id, "C:/c.trace", max_events=1, timeout_ms=1, max_file_bytes=65536
        ).ok
        worker.events_written = 1
        # Age the trace past its 1 ms budget so the quota stop stamps a timeout.
        state = service._trace_owner.get(session_id)
        assert state is not None
        state.started_monotonic -= 5.0
        result = service.trace_status(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["recording"] is False
        assert result.data["quota_stopped"] is True
        assert result.data["stop_reason"] == "timeout"
    finally:
        service.close_all()


def test_trace_status_quota_stop_keeps_the_native_reason_when_not_timed_out(
    tmp_path: Path,
) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(
            session_id, "C:/c.trace", max_events=1, timeout_ms=3_600_000, max_file_bytes=65536
        ).ok
        worker.events_written = 1
        worker.stop_reason = "breakpoint"
        # The event budget is spent but the (huge) time budget is not, so the
        # service-side stop keeps the native reason rather than stamping timeout.
        result = service.trace_status(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["recording"] is False
        assert result.data.get("quota_stopped") is not True
        assert result.data["stop_reason"] == "breakpoint"
    finally:
        service.close_all()


def test_trace_status_fails_when_the_service_side_stop_does_not_take(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    worker.stop_keeps_recording = True
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(
            session_id, "C:/c.trace", max_events=1, timeout_ms=1, max_file_bytes=65536
        ).ok
        worker.events_written = 1
        # The quota-driven trace.stop leaves recording asserted, so the status
        # poll refuses rather than pretending the trace ended.
        result = service.trace_status(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "trace_stop_failed"
    finally:
        service.close_all()


def test_trace_status_refuses_when_capability_is_missing(tmp_path: Path) -> None:
    worker = FakeTraceWorker(drop_caps=frozenset({"trace.status"}))
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        result = service.trace_status(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_trace_status_without_an_active_trace_passes_through(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    result = service.trace_status(session_id)
    assert result.ok, result.error


def test_trace_status_maps_an_unexpected_exception_on_a_live_trace(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        # The trace is still active (not finalised), so an unexpected status
        # error must finalise the partial and fail the runtime, not serve a
        # stale result.
        worker.command_errors["trace.status"] = RuntimeError("status crashed")
        result = service.trace_status(session_id)
        assert result.ok is False
        assert result.error is not None
        state = service._trace_owner.get(session_id)
        assert state is not None
        assert state.active is False
    finally:
        service.close_all()


def test_trace_status_serves_the_finalised_result_on_a_stale_rpc_error(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        assert service.trace_stop(session_id).ok
        # Trace already finalised; a late status poll that errors must still
        # answer from the retained result rather than tearing the session down.
        worker.command_errors["trace.status"] = XdbgRpcError("timeout", "stale poll")
        result = service.trace_status(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["artifact_registered"] is True
    finally:
        service.close_all()


def test_trace_status_serves_the_finalised_result_on_a_stale_exception(tmp_path: Path) -> None:
    worker = FakeTraceWorker()
    service, session_id = _launch(tmp_path, worker)
    try:
        assert service.trace_start(session_id, "C:/c.trace").ok
        assert service.trace_stop(session_id).ok
        worker.command_errors["trace.status"] = RuntimeError("stale poll")
        result = service.trace_status(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["artifact_registered"] is True
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# artifact-path and worker-loss helpers
# --------------------------------------------------------------------------


def test_new_trace_artifact_path_rejects_a_hostile_session_id(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, _, _ = trace_env
    with pytest.raises(ValueError, match="invalid session id"):
        service._new_trace_artifact_path("../escape")


def test_finalize_after_worker_loss_registers_the_partial_trace(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    assert service.trace_start(session_id, "C:/c.trace").ok
    service._finalize_trace_after_worker_loss(session_id, reason="session_closed")
    state = service._trace_owner.get(session_id)
    assert state is not None
    assert state.artifact_id is not None
    assert state.last_status["recording"] is False
    assert state.last_status["stop_reason"] == "session_closed"
    assert state.last_status["failed"] is False
    # A second call is a no-op once the artifact is registered.
    service._finalize_trace_after_worker_loss(session_id, reason="worker_failed")
    again = service._trace_owner.get(session_id)
    assert again is not None
    assert again.artifact_id == state.artifact_id


def test_finalize_after_worker_loss_ignores_a_session_without_a_trace(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    service._finalize_trace_after_worker_loss(session_id, reason="worker_failed")
    assert service._trace_owner.get(session_id) is None


# --------------------------------------------------------------------------
# trace_api_arguments
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # neither expression nor address
        {"expression": "kernel32!CreateFileW", "address": 0x1000},  # both
        {"address": 0x1000, "max_hits": 0},
        {"address": 0x1000, "max_hits": 100},
        {"address": 0x1000, "argument_count": -1},
        {"address": 0x1000, "argument_count": 9},
        {"address": 0x1000, "timeout": 0},
        {"address": 0x1000, "timeout": "soon"},
    ],
)
def test_trace_api_arguments_validates_inputs(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker], kwargs: JsonObject
) -> None:
    service, session_id, _ = trace_env
    result = service.trace_api_arguments(session_id, **kwargs)
    assert result.ok is False
    assert result.error is not None


def test_trace_api_arguments_captures_x64_register_arguments(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    result = service.trace_api_arguments(session_id, address=0x140001000, max_hits=2)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["convention"] == "microsoft_x64_integer_registers"
    assert result.data["hit_count"] == 2
    assert result.data["truncated"] is True


def test_trace_api_arguments_resolves_a_symbol_expression(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, worker = trace_env
    worker.symbol_address = 0x140001000
    result = service.trace_api_arguments(
        session_id, expression="kernel32!CreateFileW", max_hits=1
    )
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["target"]["address"] == 0x140001000
    assert result.data["target"]["resolution"] is not None


def test_trace_api_arguments_rejects_a_symbol_without_an_address(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, worker = trace_env
    worker.symbol_address = None
    result = service.trace_api_arguments(session_id, expression="bogus!symbol")
    assert result.ok is False
    assert result.error is not None


def test_trace_api_arguments_returns_a_failed_symbol_resolution(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, worker = trace_env
    worker.command_errors["symbols.resolve"] = XdbgRpcError("not_found", "no such symbol")
    result = service.trace_api_arguments(session_id, expression="missing!symbol")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_trace_api_arguments_stops_when_a_resume_fails(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, worker = trace_env
    worker.command_errors["debug.resume"] = XdbgRpcError("backend_error", "cannot resume")
    result = service.trace_api_arguments(session_id, address=0x140001000, max_hits=3)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["hit_count"] == 0


def test_trace_api_arguments_stops_when_the_break_is_elsewhere(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, _ = trace_env
    # The fake always parks rip at 0x140001000; a different target reads as a
    # break somewhere else and ends the capture.
    result = service.trace_api_arguments(session_id, address=0x140002000, max_hits=3)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["stopped_elsewhere"] is True
    assert result.data["hit_count"] == 0


def test_trace_api_arguments_returns_when_arming_fails(
    trace_env: tuple[AnalysisService, str, FakeTraceWorker],
) -> None:
    service, session_id, worker = trace_env
    worker.command_errors["breakpoints.set"] = XdbgRpcError("backend_error", "cannot arm")
    result = service.trace_api_arguments(session_id, address=0x140001000)
    assert result.ok is False
    assert result.error is not None


def test_trace_api_arguments_captures_x86_stack_arguments(tmp_path: Path) -> None:
    worker = FakeTraceWorker(architecture="x86")
    service, session_id = _launch(tmp_path, worker, machine=0x014C)
    try:
        result = service.trace_api_arguments(session_id, address=0x140001000, max_hits=1)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["convention"] == "x86_stack_arguments"
        assert result.data["hit_count"] == 1
    finally:
        service.close_all()
