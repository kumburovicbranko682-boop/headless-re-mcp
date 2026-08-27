"""XdbgClient must bound its own arguments and distrust the worker's replies.

The named-pipe transport is Windows-only, but the request-building and
reply-validating logic above it is portable and is where a hostile or buggy
x64dbg worker would do damage. This module drives that surface without a pipe:

* ``XdbgRpcError.from_payload`` turning an arbitrary error payload into a
  structured error (and degrading a non-dict / non-dict-details shape),
* ``_validate_trace_result`` -- a static, pure guard -- rejecting every
  malformed trace reply and filling the tolerated defaults,
* ``trace_start`` bounding its path / counts / byte budget before dispatch,
  and ``trace_stop`` / ``trace_status`` / ``trace_cancel`` dispatch and the
  ``initialized is False`` skip, and
* ``request`` failing closed when the client is closed, the worker has exited,
  or the method is outside the negotiated capability set.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from threading import Lock, RLock
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError

JsonObject = dict[str, Any]


# --------------------------------------------------------------------------
# XdbgRpcError.from_payload
# --------------------------------------------------------------------------


def test_from_payload_rejects_a_non_dict_shape() -> None:
    error = XdbgRpcError.from_payload(["not", "a", "dict"])
    assert error.code == "rpc_protocol_error"
    assert error.details == {}
    assert error.retryable is False


def test_from_payload_preserves_a_structured_error() -> None:
    error = XdbgRpcError.from_payload(
        {"code": "bad_state", "message": "nope", "details": {"field": "x"}, "retryable": True}
    )
    assert error.code == "bad_state"
    assert str(error) == "nope"
    assert error.details == {"field": "x"}
    assert error.retryable is True


def test_from_payload_defaults_missing_fields_and_drops_non_dict_details() -> None:
    error = XdbgRpcError.from_payload({"details": "not-a-map"})
    assert error.code == "backend_error"
    assert "failed" in str(error)
    assert error.details == {}
    assert error.retryable is False


# --------------------------------------------------------------------------
# _validate_trace_result (static, pure)
# --------------------------------------------------------------------------


def _trace_result(**overrides: Any) -> JsonObject:
    result: JsonObject = {
        "recording": True,
        "events_written": 1,
        "file_bytes": 2,
        "elapsed_ms": 3,
        "stop_reason": "done",
    }
    result.update(overrides)
    return result


def test_validate_trace_requires_a_boolean_recording_state() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result(_trace_result(recording="yes"))
    assert exc.value.code == "rpc_protocol_error"


def test_validate_trace_rejects_a_recording_state_mismatch() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result(_trace_result(recording=True), recording=False)
    assert exc.value.code == "rpc_protocol_error"
    assert exc.value.details == {"expected": False, "actual": True}


def test_validate_trace_rejects_an_unparseable_returned_path() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result(
            _trace_result(path="bad\x00path"), path=Path("/tmp/hre/run.bin")
        )
    assert exc.value.code == "rpc_protocol_error"


def test_validate_trace_rejects_a_path_that_does_not_match() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result(
            _trace_result(path="/tmp/hre/other.bin"), path=Path("/tmp/hre/run.bin")
        )
    assert exc.value.code == "rpc_protocol_error"


@pytest.mark.parametrize(
    "bound", [{"max_events": 99}, {"timeout_ms": 99}, {"max_file_bytes": 99}]
)
def test_validate_trace_rejects_a_bound_the_worker_did_not_echo(bound: JsonObject) -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result(_trace_result(), **bound)
    assert exc.value.code == "rpc_protocol_error"
    assert next(iter(bound)) in str(exc.value)


def test_validate_trace_defaults_missing_counters_to_zero() -> None:
    result = _trace_result()
    del result["events_written"]
    XdbgClient._validate_trace_result(result)
    assert result["events_written"] == 0


@pytest.mark.parametrize("bad", [{"file_bytes": "x"}, {"elapsed_ms": -1}])
def test_validate_trace_rejects_a_non_integer_or_negative_counter(bad: JsonObject) -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result(_trace_result(**bad))
    assert exc.value.code == "rpc_protocol_error"


def test_validate_trace_replaces_a_blank_stop_reason_with_none() -> None:
    result = _trace_result(stop_reason="")
    XdbgClient._validate_trace_result(result)
    assert result["stop_reason"] == "none"


def test_validate_trace_accepts_a_well_formed_result() -> None:
    result = _trace_result(recording=False)
    XdbgClient._validate_trace_result(result, recording=False)
    assert result["stop_reason"] == "done"


# --------------------------------------------------------------------------
# trace_start / trace_stop / trace_status / trace_cancel dispatch
# --------------------------------------------------------------------------


def _dispatch_client(result: JsonObject) -> tuple[XdbgClient, list[tuple[str, JsonObject, float]]]:
    client = object.__new__(XdbgClient)
    calls: list[tuple[str, JsonObject, float]] = []

    def request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        calls.append((method, params or {}, timeout))
        return dict(result)

    client.request = request  # type: ignore[method-assign]
    return client, calls


def test_trace_start_requires_an_absolute_path() -> None:
    client, _ = _dispatch_client({})
    with pytest.raises(ValueError, match="absolute"):
        client.trace_start("relative/run.bin")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_events": 0},
        {"max_events": 1_000_001},
        {"max_events": True},
        {"timeout_ms": 0},
        {"timeout_ms": 3_600_001},
        {"max_file_bytes": 0},
        {"max_file_bytes": 256 * 1024 * 1024 + 1},
    ],
)
def test_trace_start_rejects_out_of_range_bounds(kwargs: JsonObject) -> None:
    client, calls = _dispatch_client({})
    with pytest.raises(ValueError):
        client.trace_start("/tmp/hre/run.bin", **kwargs)
    assert calls == []


def test_trace_start_dispatches_and_validates_the_reply() -> None:
    path = "/tmp/hre/run.bin"
    result = {
        "recording": True,
        "path": path,
        "max_events": 10,
        "timeout_ms": 1000,
        "max_file_bytes": 4096,
        "events_written": 0,
        "file_bytes": 0,
        "elapsed_ms": 0,
        "stop_reason": "none",
    }
    client, calls = _dispatch_client(result)
    out = client.trace_start(path, max_events=10, timeout_ms=1000, max_file_bytes=4096)
    assert calls[0][0] == "trace.start"
    assert calls[0][1]["path"] == path
    assert calls[0][1]["max_events"] == 10
    assert out["recording"] is True


def test_trace_stop_skips_validation_when_uninitialized() -> None:
    client, calls = _dispatch_client({"initialized": False})
    out = client.trace_stop()
    assert out == {"initialized": False}
    assert calls[0][0] == "trace.stop"


def test_trace_stop_validates_a_finished_recording() -> None:
    client, _ = _dispatch_client(_trace_result(recording=False))
    out = client.trace_stop()
    assert out["recording"] is False


def test_trace_cancel_delegates_to_trace_stop() -> None:
    client, calls = _dispatch_client(_trace_result(recording=False))
    client.trace_cancel()
    assert calls[0][0] == "trace.stop"


def test_trace_status_validates_the_reply() -> None:
    client, calls = _dispatch_client(_trace_result())
    client.trace_status()
    assert calls[0][0] == "trace.status"


# --------------------------------------------------------------------------
# thin RPC wrappers build the right method + params
# --------------------------------------------------------------------------


def test_thin_wrappers_dispatch_the_expected_method_and_params() -> None:
    """Each one-line wrapper is the client's contract with the worker.

    A wrong method name or param key is a silent break the transport cannot
    catch, so pin the exact frame every wrapper builds -- including whether an
    optional argument is included or dropped.
    """
    client, calls = _dispatch_client({"ok": True})

    client.memory_regions(offset=2, limit=10)
    client.memory_regions()
    client.memory_protect_query(0x1004)
    client.memory_protection(0x1000, rights="rwx")
    client.memory_protection(0x2000)
    client.threads_list(offset=1, limit=8)
    client.threads_current()
    client.threads_context_read(11)
    client.threads_context_write(11, "rax", 0xDEAD)
    client.stack_read(address=0x3000, count=4)
    client.stack_read(count=2)
    client.stack_trace(limit=16)
    client.disassembly_read(0x4000, count=3)
    client.symbols_list(0x400000, limit=32)
    client.symbols_resolve("kernel32.dll!Sleep")
    client.breakpoints_hardware_set(0x5000, bp_type="w", size=4)
    client.breakpoints_hardware_remove(0x5000)
    client.breakpoints_hardware_list()
    client.breakpoints_memory_set(0x6000, bp_type="r")
    client.breakpoints_memory_remove(0x6000)
    client.breakpoints_memory_list()
    client.breakpoints_condition_set(0x7000, "eax==1")
    client.breakpoints_condition_get(0x7000)
    client.patches_list()
    client.patches_apply(0x8000, "9090")
    client.patches_restore(0x8000)
    client.modules_dump(0x400000, "/tmp/mod.bin", size=0x1000)
    client.modules_dump(0x400000, "/tmp/mod.bin")
    client.pe_headers_runtime(0x400000, output_path="/tmp/pe.bin")
    client.pe_headers_runtime(0x400000)
    client.imports_scan(
        0x400000, search_start=1, search_size=2, max_candidates=3, mode="iat"
    )
    client.imports_scan(0x400000)
    client.imports_read(0x9000, 0x40)

    observed = [(method, params) for method, params, _ in calls]
    assert observed == [
        ("memory.regions", {"offset": 2, "limit": 10}),
        ("memory.regions", {"offset": 0}),
        ("memory.protect.query", {"address": 0x1004}),
        ("memory.protection", {"address": 0x1000, "rights": "rwx"}),
        ("memory.protection", {"address": 0x2000}),
        ("threads.list", {"offset": 1, "limit": 8}),
        ("threads.current", {}),
        ("threads.context.read", {"tid": 11}),
        ("threads.context.write", {"tid": 11, "name": "rax", "value": 0xDEAD}),
        ("stack.read", {"count": 4, "address": 0x3000}),
        ("stack.read", {"count": 2}),
        ("stack.trace", {"limit": 16}),
        ("disassembly.read", {"address": 0x4000, "count": 3}),
        ("symbols.list", {"module_base": 0x400000, "limit": 32}),
        ("symbols.resolve", {"expression": "kernel32.dll!Sleep"}),
        ("breakpoints.hardware.set", {"address": 0x5000, "type": "w", "size": 4}),
        ("breakpoints.hardware.remove", {"address": 0x5000}),
        ("breakpoints.hardware.list", {}),
        ("breakpoints.memory.set", {"address": 0x6000, "type": "r"}),
        ("breakpoints.memory.remove", {"address": 0x6000}),
        ("breakpoints.memory.list", {}),
        ("breakpoints.condition.set", {"address": 0x7000, "expression": "eax==1"}),
        ("breakpoints.condition.get", {"address": 0x7000}),
        ("patches.list", {}),
        ("patches.apply", {"address": 0x8000, "data": "9090"}),
        ("patches.restore", {"address": 0x8000}),
        ("modules.dump", {"base": 0x400000, "output_path": "/tmp/mod.bin", "size": 0x1000}),
        ("modules.dump", {"base": 0x400000, "output_path": "/tmp/mod.bin"}),
        ("pe.headers.runtime", {"base": 0x400000, "output_path": "/tmp/pe.bin"}),
        ("pe.headers.runtime", {"base": 0x400000}),
        (
            "imports.scan",
            {
                "module_base": 0x400000,
                "search_start": 1,
                "search_size": 2,
                "max_candidates": 3,
                "mode": "iat",
            },
        ),
        ("imports.scan", {"module_base": 0x400000}),
        ("imports.read", {"iat_va": 0x9000, "size": 0x40}),
    ]


# --------------------------------------------------------------------------
# request() fail-closed guards
# --------------------------------------------------------------------------


class _Proc:
    def __init__(self, returncode: int | None) -> None:
        self._returncode = returncode
        self.pid = 4321

    def poll(self) -> int | None:
        return self._returncode


def _guard_client(
    *,
    closed: bool = False,
    returncode: int | None = None,
    capabilities: frozenset[str] = frozenset({"events.read"}),
) -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_lock = RLock()
    client._closed = closed
    client._capabilities = capabilities
    client._transport = object()  # type: ignore[assignment]
    client._process = _Proc(returncode)  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=10)
    client._stderr_log = deque(maxlen=10)
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    return client


def test_request_on_a_closed_client_is_refused() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _guard_client(closed=True).request("events.read")
    assert exc.value.code == "session_closed"


def test_request_after_the_worker_exits_reports_worker_exited() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _guard_client(returncode=7).request("events.read")
    assert exc.value.code == "worker_exited"
    assert exc.value.details["exit_code"] == 7
    assert exc.value.retryable is True


def test_request_refuses_a_method_outside_the_capability_set() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _guard_client().request("memory.regions")
    assert exc.value.code == "capability_unavailable"
    assert exc.value.details == {"capability": "memory.regions"}
