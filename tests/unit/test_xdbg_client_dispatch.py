"""Dispatch, trace-validation, and gate contracts for the x64dbg RPC client.

``test_xdbg_client`` drives the named-pipe framing, ``read_events``,
``wait_for_state``, ``close``, and reconnect. This file covers the parts that
stay pure Python on every platform: the thin request wrappers' parameter
shaping, the ``trace.*`` lifecycle and its ``_validate_trace_result`` guard, the
``request`` capability/closed/exit gate, ``_note_debuggee_pid`` parsing, and the
``seed_headless_event_settings`` / ``from_payload`` helpers. None of it touches
the Win32 transport, so it runs on the Linux CI job too.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from threading import Lock, RLock
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import (
    XdbgClient,
    XdbgRpcError,
    seed_headless_event_settings,
)

JsonObject = dict[str, Any]


class _FakeProcess:
    def __init__(self, returncode: int | None = None) -> None:
        self.pid = 4242
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode


def _dispatch_client() -> tuple[XdbgClient, list[tuple[str, JsonObject, float]]]:
    """A bare client whose ``request`` records what each wrapper dispatched."""
    client = object.__new__(XdbgClient)
    calls: list[tuple[str, JsonObject, float]] = []

    def request(
        method: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        calls.append((method, params or {}, timeout))
        return {"method": method, **(params or {})}

    client.request = request  # type: ignore[method-assign]
    return client, calls


# ---------------------------------------------------------------------------
# Request wrappers
# ---------------------------------------------------------------------------


def test_request_wrappers_shape_params_and_pick_methods() -> None:
    client, calls = _dispatch_client()

    client.memory_protection(0x10, timeout=3)
    client.memory_protection(0x10, rights="rwx", timeout=3)
    client.threads_list(offset=4, limit=8, timeout=3)
    client.threads_current(timeout=3)
    client.threads_context_read(7, timeout=3)
    client.threads_context_write(7, "rax", 0x99, timeout=3)
    client.stack_read(count=16, timeout=3)
    client.stack_read(address=0x2000, count=16, timeout=3)
    client.stack_trace(limit=12, timeout=3)
    client.disassembly_read(0x401000, count=4, timeout=3)
    client.symbols_list(0x400000, limit=32, timeout=3)
    client.symbols_resolve("kernel32.CreateFileW", timeout=3)
    client.breakpoints_hardware_set(0x401000, bp_type="w", size=4, timeout=3)
    client.breakpoints_hardware_remove(0x401000, timeout=3)
    client.breakpoints_hardware_list(timeout=3)
    client.breakpoints_memory_set(0x402000, bp_type="a", timeout=3)
    client.breakpoints_memory_remove(0x402000, timeout=3)
    client.breakpoints_memory_list(timeout=3)
    client.breakpoints_condition_set(0x403000, "rax==0", timeout=3)
    client.breakpoints_condition_get(0x403000, timeout=3)
    client.patches_list(timeout=3)
    client.patches_apply(0x404000, "9090", timeout=3)
    client.patches_restore(0x404000, timeout=3)
    client.imports_read(0x405000, 0x40, timeout=3)
    # Default (None) optional args must be omitted from the params entirely.
    client.memory_regions(offset=1, timeout=3)
    client.modules_dump(0x400000, Path("/tmp/mod.bin"), timeout=3)

    methods_and_params = [(method, params) for method, params, _ in calls]
    assert methods_and_params == [
        ("memory.protection", {"address": 0x10}),
        ("memory.protection", {"address": 0x10, "rights": "rwx"}),
        ("threads.list", {"offset": 4, "limit": 8}),
        ("threads.current", {}),
        ("threads.context.read", {"tid": 7}),
        ("threads.context.write", {"tid": 7, "name": "rax", "value": 0x99}),
        ("stack.read", {"count": 16}),
        ("stack.read", {"count": 16, "address": 0x2000}),
        ("stack.trace", {"limit": 12}),
        ("disassembly.read", {"address": 0x401000, "count": 4}),
        ("symbols.list", {"module_base": 0x400000, "limit": 32}),
        ("symbols.resolve", {"expression": "kernel32.CreateFileW"}),
        ("breakpoints.hardware.set", {"address": 0x401000, "type": "w", "size": 4}),
        ("breakpoints.hardware.remove", {"address": 0x401000}),
        ("breakpoints.hardware.list", {}),
        ("breakpoints.memory.set", {"address": 0x402000, "type": "a"}),
        ("breakpoints.memory.remove", {"address": 0x402000}),
        ("breakpoints.memory.list", {}),
        ("breakpoints.condition.set", {"address": 0x403000, "expression": "rax==0"}),
        ("breakpoints.condition.get", {"address": 0x403000}),
        ("patches.list", {}),
        ("patches.apply", {"address": 0x404000, "data": "9090"}),
        ("patches.restore", {"address": 0x404000}),
        ("imports.read", {"iat_va": 0x405000, "size": 0x40}),
        ("memory.regions", {"offset": 1}),
        ("modules.dump", {"base": 0x400000, "output_path": str(Path("/tmp/mod.bin"))}),
    ]
    assert all(timeout == 3 for _, _, timeout in calls)


def test_pe_headers_runtime_only_includes_output_path_when_given() -> None:
    client, calls = _dispatch_client()

    client.pe_headers_runtime(0x400000)
    client.pe_headers_runtime(0x400000, output_path=Path("/tmp/out/pe.json"))

    assert calls[0][1] == {"base": 0x400000}
    assert calls[1][1] == {
        "base": 0x400000,
        "output_path": str(Path("/tmp/out/pe.json")),
    }


def test_imports_scan_appends_only_the_optional_params_provided() -> None:
    client, calls = _dispatch_client()

    client.imports_scan(0x400000)
    client.imports_scan(
        0x400000,
        search_start=0x1000,
        search_size=0x2000,
        max_candidates=5,
        mode="strict",
    )

    assert calls[0][1] == {"module_base": 0x400000}
    assert calls[1][1] == {
        "module_base": 0x400000,
        "search_start": 0x1000,
        "search_size": 0x2000,
        "max_candidates": 5,
        "mode": "strict",
    }


# ---------------------------------------------------------------------------
# Trace lifecycle + validation
# ---------------------------------------------------------------------------


def _valid_trace(path: Path) -> JsonObject:
    return {
        "recording": True,
        "path": str(path),
        "max_events": 10_000,
        "timeout_ms": 60_000,
        "max_file_bytes": 16 * 1024 * 1024,
        "events_written": 0,
        "file_bytes": 0,
        "elapsed_ms": 0,
        "stop_reason": "running",
    }


def test_trace_start_validates_bounds_before_dispatching() -> None:
    client, calls = _dispatch_client()

    # The bound checks run only after the absolute-path guard, so the paths
    # below must be absolute on the running platform (a leading "/" is not
    # absolute on Windows, which has no drive letter) or the absolute guard
    # fires first and the bound assertions never see their own error.
    absolute = str(Path.cwd() / "t.bin")

    with pytest.raises(ValueError, match="absolute"):
        client.trace_start("relative/trace.bin")
    with pytest.raises(ValueError, match="max_events"):
        client.trace_start(absolute, max_events=0)
    with pytest.raises(ValueError, match="timeout_ms"):
        client.trace_start(absolute, timeout_ms=0)
    with pytest.raises(ValueError, match="max_file_bytes"):
        client.trace_start(absolute, max_file_bytes=0)

    assert calls == []


def test_trace_start_dispatches_and_accepts_a_matching_result(tmp_path: Path) -> None:
    trace_path = tmp_path / "trace.bin"
    client = object.__new__(XdbgClient)

    def request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        del timeout
        assert method == "trace.start"
        assert params is not None
        return _valid_trace(Path(params["path"]))

    client.request = request  # type: ignore[method-assign]

    result = client.trace_start(trace_path, max_events=10_000)
    assert result["recording"] is True
    assert Path(result["path"]) == trace_path


def test_trace_stop_and_status_skip_validation_when_uninitialized() -> None:
    client = object.__new__(XdbgClient)
    payloads = iter(({"initialized": False}, {"initialized": False}))

    def request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        del params, timeout
        assert method in {"trace.stop", "trace.status"}
        return next(payloads)

    client.request = request  # type: ignore[method-assign]

    assert client.trace_stop() == {"initialized": False}
    assert client.trace_status() == {"initialized": False}


def test_trace_status_validates_an_initialized_result(tmp_path: Path) -> None:
    client = object.__new__(XdbgClient)

    def request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        del params, timeout
        assert method == "trace.status"
        result = _valid_trace(tmp_path / "trace.bin")
        result["recording"] = False
        return result

    client.request = request  # type: ignore[method-assign]

    status = client.trace_status()
    assert status["recording"] is False
    assert status["stop_reason"] == "running"


def test_trace_cancel_delegates_to_stop_and_validates_when_recording() -> None:
    client = object.__new__(XdbgClient)

    def request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        del params, timeout
        assert method == "trace.stop"
        result = _valid_trace(Path("/tmp/whatever.bin"))
        result["recording"] = False
        return result

    client.request = request  # type: ignore[method-assign]

    stopped = client.trace_cancel()
    assert stopped["recording"] is False


def test_validate_trace_result_normalizes_missing_counters_and_reason() -> None:
    result: JsonObject = {"recording": False}
    XdbgClient._validate_trace_result(result, recording=False)
    assert result["events_written"] == 0
    assert result["file_bytes"] == 0
    assert result["elapsed_ms"] == 0
    assert result["stop_reason"] == "none"


@pytest.mark.parametrize(
    ("result", "match"),
    [
        ({"recording": "yes"}, "boolean recording"),
        ({"recording": True}, "unexpected trace recording"),
    ],
)
def test_validate_trace_result_rejects_bad_recording_state(result: JsonObject, match: str) -> None:
    with pytest.raises(XdbgRpcError, match=match):
        XdbgClient._validate_trace_result(result, recording=False)


def test_validate_trace_result_checks_the_returned_path(tmp_path: Path) -> None:
    wanted = tmp_path / "trace.bin"
    good = {"recording": True, "path": str(wanted)}
    XdbgClient._validate_trace_result(good, path=wanted, recording=True)

    with pytest.raises(XdbgRpcError, match="different trace path"):
        XdbgClient._validate_trace_result(
            {"recording": True, "path": str(tmp_path / "other.bin")},
            path=wanted,
            recording=True,
        )

    # An embedded null byte makes Path(...).resolve() raise, which the guard
    # reports as an invalid path rather than a mismatch.
    with pytest.raises(XdbgRpcError, match="invalid trace path"):
        XdbgClient._validate_trace_result(
            {"recording": True, "path": "bad\x00path"}, path=wanted, recording=True
        )


def test_validate_trace_result_flags_mismatched_bounds() -> None:
    with pytest.raises(XdbgRpcError, match="unexpected max_events"):
        XdbgClient._validate_trace_result(
            {"recording": True, "max_events": 5}, max_events=10, recording=True
        )


@pytest.mark.parametrize("bad", [{"events_written": -1}, {"file_bytes": "x"}])
def test_validate_trace_result_rejects_bad_counters(bad: JsonObject) -> None:
    result: JsonObject = {"recording": False, **bad}
    with pytest.raises(XdbgRpcError, match="invalid"):
        XdbgClient._validate_trace_result(result, recording=False)


# ---------------------------------------------------------------------------
# request() gate
# ---------------------------------------------------------------------------


def _gate_client(
    *,
    closed: bool = False,
    returncode: int | None = None,
    capabilities: frozenset[str] = frozenset({"memory.regions"}),
) -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_lock = RLock()
    client._closed = closed
    client._process = _FakeProcess(returncode)  # type: ignore[assignment]
    client._capabilities = capabilities
    client._transport = object()  # type: ignore[assignment]
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    client._stdout_log = deque(maxlen=10)
    client._stderr_log = deque(maxlen=10)
    return client


def test_request_refuses_once_closed() -> None:
    client = _gate_client(closed=True)
    with pytest.raises(XdbgRpcError) as caught:
        client.request("memory.regions")
    assert caught.value.code == "session_closed"


def test_request_reports_a_dead_worker() -> None:
    client = _gate_client(returncode=5)
    with pytest.raises(XdbgRpcError) as caught:
        client.request("memory.regions")
    assert caught.value.code == "worker_exited"
    assert caught.value.details["exit_code"] == 5


def test_request_refuses_an_uncapable_method_before_the_transport() -> None:
    client = _gate_client(capabilities=frozenset())
    with pytest.raises(XdbgRpcError) as caught:
        client.request("memory.regions")
    assert caught.value.code == "capability_unavailable"
    assert caught.value.details["capability"] == "memory.regions"


def test_request_lets_rpc_prefixed_methods_bypass_the_capability_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _gate_client(capabilities=frozenset())
    seen: list[str] = []

    def _request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        del params, timeout
        seen.append(method)
        return {"ok": True}

    monkeypatch.setattr(client, "_observe_windows", lambda: None)
    monkeypatch.setattr(client, "_request", _request)
    assert client.request("rpc.ping") == {"ok": True}
    assert seen == ["rpc.ping"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"process_id": 321}, 321),
        ({"debuggee_pid": "654"}, 654),
        ({"process_id": 0}, None),
        ({"debuggee_pid": "0"}, None),
        ({"process_id": "notapid"}, None),
        ({"process_id": None, "debuggee_pid": None}, None),
    ],
)
def test_note_debuggee_pid_parses_only_positive_pids(
    payload: JsonObject, expected: int | None
) -> None:
    client = object.__new__(XdbgClient)
    client._window_lock = Lock()
    client._debuggee_pid = 99
    client._note_debuggee_pid(payload)
    assert client._debuggee_pid == expected


def test_note_debuggee_pid_ignores_payloads_without_a_pid_field() -> None:
    client = object.__new__(XdbgClient)
    client._window_lock = Lock()
    client._debuggee_pid = 77
    client._note_debuggee_pid({"unrelated": "value"})
    assert client._debuggee_pid == 77


def test_seed_headless_event_settings_writes_once_and_is_idempotent(
    tmp_path: Path,
) -> None:
    path = seed_headless_event_settings(tmp_path)
    assert path.exists()
    first = path.read_text(encoding="utf-8")

    # A second call must not overwrite a user's edited ini.
    path.write_text(first + "\n; edited\n", encoding="utf-8")
    again = seed_headless_event_settings(tmp_path)
    assert again == path
    assert again.read_text(encoding="utf-8").endswith("; edited\n")


def test_from_payload_rejects_non_dict_payloads() -> None:
    error = XdbgRpcError.from_payload(["not", "a", "dict"])
    assert error.code == "rpc_protocol_error"
    assert error.retryable is False


def test_properties_expose_pid_capabilities_and_metadata() -> None:
    client = object.__new__(XdbgClient)
    client._process = _FakeProcess()  # type: ignore[assignment]
    client._capabilities = frozenset({"memory.regions"})
    client._metadata = {"architecture": "x64"}
    assert client.pid == 4242
    assert client.exit_code is None
    assert client.capabilities == frozenset({"memory.regions"})
    # metadata returns a defensive copy.
    snapshot = client.metadata
    snapshot["architecture"] = "mutated"
    assert client.metadata == {"architecture": "x64"}
