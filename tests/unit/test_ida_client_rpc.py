"""The IDA worker RPC client against a scripted in-process worker.

``IdaWorkerClient`` sits between the service and an idalib subprocess that
parses attacker-supplied binaries. Everything the worker sends back is hostile
input: these tests script the worker end of the pipe and pin how the client
maps each protocol failure (bad envelopes, floods, silence, death, analyzer
windows) to a typed error instead of hanging or trusting the payload.
"""

from __future__ import annotations

import io
import json
import queue
import subprocess
from collections import deque
from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import Any

import pytest

import headless_re_mcp.backends.ida.client as client_module
from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError
from headless_re_mcp.config import Settings

JsonObject = dict[str, Any]


class _PipeStream:
    """A blocking, feedable text stream standing in for a worker pipe."""

    def __init__(self) -> None:
        self._lines: queue.Queue[str | None] = queue.Queue()

    def feed(self, text: str) -> None:
        self._lines.put(text if text.endswith("\n") else text + "\n")

    def feed_json(self, payload: object) -> None:
        self.feed(json.dumps(payload, ensure_ascii=False))

    def eof(self) -> None:
        self._lines.put(None)

    def readline(self, size: int = -1) -> str:
        item = self._lines.get()
        return "" if item is None else item


class _Stdin:
    """Captures client requests and hands them to a per-test responder."""

    def __init__(self, process: _FakeWorker) -> None:
        self._process = process
        self.closed = False

    def write(self, text: str) -> int:
        request = json.loads(text)
        responder = self._process.responder
        if responder is not None:
            responder(request)
        return len(text)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeWorker:
    pid = 4321

    def __init__(self) -> None:
        self.stdout = _PipeStream()
        self.stderr = _PipeStream()
        self.stdin = _Stdin(self)
        self.responder: Callable[[JsonObject], None] | None = None
        self.exit_code: int | None = None
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.exit_code

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.exit_code is None:
            raise subprocess.TimeoutExpired(cmd="ida-worker", timeout=timeout or 0.0)
        return self.exit_code

    def reply_ok(self, request: JsonObject, data: JsonObject) -> None:
        self.stdout.feed_json({"id": request["id"], "ok": True, "data": data})

    def reply_error(self, request: JsonObject, error: object) -> None:
        self.stdout.feed_json({"id": request["id"], "ok": False, "error": error})


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=tmp_path,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _make_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ready: object | None = None,
) -> tuple[IdaWorkerClient, _FakeWorker, list[Any]]:
    """Boot a client against a fake worker that already announced readiness."""
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    process = _FakeWorker()
    if ready is None:
        ready = {"event": "ready", "data": {"capabilities": ["decompile"], "version": "9.0"}}
    process.stdout.feed_json(ready)

    reaped: list[Any] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(client_module, "assign_to_process_group", lambda pid: None)
    monkeypatch.setattr(client_module, "describe_process_windows", lambda pid: [])
    monkeypatch.setattr(
        client_module,
        "terminate_process_tree",
        lambda proc, wait_s=5.0: reaped.append(proc),
    )
    client = IdaWorkerClient(binary, _settings(tmp_path), startup_timeout=5.0)
    return client, process, reaped


def _shutdown(client: IdaWorkerClient, process: _FakeWorker) -> None:
    """Unblock the reader threads so they exit instead of piling up."""
    process.stdout.eof()
    process.stderr.eof()
    client._stdout_thread.join(timeout=1.0)
    client._stderr_thread.join(timeout=1.0)


def test_an_unconfigured_ida_home_is_refused_before_any_process_starts(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    object.__setattr__(settings, "ida_home", None)

    with pytest.raises(IdaWorkerError) as excinfo:
        IdaWorkerClient(tmp_path / "sample.exe", settings)

    assert excinfo.value.code == "backend_unavailable"


def test_a_fatal_startup_event_surfaces_the_worker_error_and_reaps_the_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(IdaWorkerError) as excinfo:
        _make_client(
            tmp_path,
            monkeypatch,
            ready={
                "event": "fatal",
                "error": {
                    "code": "worker_start_failed",
                    "message": "database already open",
                    "retryable": True,
                },
            },
        )

    assert excinfo.value.code == "worker_start_failed"
    assert excinfo.value.retryable is True


def test_a_ready_event_without_a_data_object_is_a_protocol_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(IdaWorkerError) as excinfo:
        _make_client(tmp_path, monkeypatch, ready={"event": "ready", "data": 5})

    assert excinfo.value.code == "worker_protocol_error"


def test_startup_metadata_is_copied_and_bogus_capabilities_stay_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(
        tmp_path,
        monkeypatch,
        ready={"event": "ready", "data": {"capabilities": "not-a-list", "version": "9.0"}},
    )
    try:
        assert client.pid == 4321
        assert client.exit_code is None
        assert client.capabilities == frozenset()
        snapshot = client.metadata
        snapshot["version"] = "tampered"
        assert client.metadata["version"] == "9.0"
        assert client.analyzer_windows == ()
    finally:
        _shutdown(client, process)


def test_a_request_round_trips_and_unwraps_the_data_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    seen: list[JsonObject] = []

    def responder(request: JsonObject) -> None:
        seen.append(request)
        process.reply_ok(request, {"functions": 12})

    process.responder = responder
    try:
        data = client.request("functions.count", {"module": "main"}, timeout=5.0)
    finally:
        _shutdown(client, process)

    assert data == {"functions": 12}
    assert seen[0]["command"] == "functions.count"
    assert seen[0]["params"] == {"module": "main"}
    assert client.capabilities == frozenset({"decompile"})


def test_a_worker_error_envelope_becomes_a_typed_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.responder = lambda request: process.reply_error(
        request,
        {"code": "decompiler_unavailable", "message": "no license", "retryable": False},
    )
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("decompile", timeout=5.0)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "decompiler_unavailable"
    assert "no license" in str(excinfo.value)


def test_an_ok_response_without_a_data_object_is_a_protocol_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.responder = lambda request: process.stdout.feed_json(
        {"id": request["id"], "ok": True, "data": [1, 2, 3]}
    )
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=5.0)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_protocol_error"


def test_a_malformed_error_payload_still_produces_a_usable_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.responder = lambda request: process.reply_error(request, "not a dict")
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=5.0)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_protocol_error"
    assert excinfo.value.retryable is False


def test_requests_after_close_are_refused_without_touching_the_pipe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    client._closed = True
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info")
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "session_closed"


def test_a_dead_worker_is_reported_with_its_exit_code_and_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.stderr.feed("idalib: segmentation fault")
    client._stderr_thread.join(timeout=0.0)  # nudge scheduling; log fills async
    process.exit_code = 139
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info")
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_exited"
    assert "139" in str(excinfo.value)
    assert excinfo.value.retryable is True
    assert excinfo.value.details["exit_code"] == 139


def test_a_broken_stdin_pipe_is_reported_as_a_worker_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)

    def explode(request: JsonObject) -> None:
        raise BrokenPipeError("worker went away")

    process.responder = explode
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info")
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_exited"


def test_a_silent_worker_times_out_and_is_reaped_as_unsafe_to_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, reaped = _make_client(tmp_path, monkeypatch)
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=0.2)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_timeout"
    assert excinfo.value.retryable is True
    assert reaped, "a timed-out worker is still inside Hex-Rays and must be reaped"


def test_a_message_flood_surfaces_as_overflow_and_retires_the_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, reaped = _make_client(tmp_path, monkeypatch)
    client._message_overflow.set()
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=5.0)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_output_overflow"
    assert excinfo.value.retryable is True
    assert reaped, "an overflowed worker has lost protocol messages and must be reaped"


def test_a_worker_dying_mid_wait_is_detected_without_burning_the_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)

    def die_silently(request: JsonObject) -> None:
        process.exit_code = 1

    process.responder = die_silently
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=30.0)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "worker_exited"


def test_an_eof_on_stdout_is_reported_as_a_worker_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.responder = lambda request: process.stdout.eof()
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=5.0)
    finally:
        process.stderr.eof()
        client._stderr_thread.join(timeout=1.0)
        client._stdout_thread.join(timeout=1.0)

    assert excinfo.value.code == "worker_exited"


def test_unsolicited_noise_is_logged_while_progress_slips_through_quietly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)

    def responder(request: JsonObject) -> None:
        process.stdout.feed_json({"event": "progress", "step": "auto_wait"})
        process.stdout.feed_json({"event": "telemetry", "leaked": "yes"})
        process.reply_ok(request, {"ok": "sure"})

    process.responder = responder
    try:
        data = client.request("info", timeout=5.0)
    finally:
        _shutdown(client, process)

    assert data == {"ok": "sure"}
    log = "\n".join(client._stdout_log)
    assert "telemetry" in log, "non-progress noise must land in diagnostics"
    assert "progress" not in log, "progress events are expected and not noise"


def test_an_analyzer_window_refuses_the_call_and_is_remembered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(
        client_module, "describe_process_windows", lambda pid: ["IDA: license dialog"]
    )
    try:
        with pytest.raises(IdaWorkerError) as excinfo:
            client.request("info", timeout=5.0)
    finally:
        _shutdown(client, process)

    assert excinfo.value.code == "analyzer_window_detected"
    assert excinfo.value.details == {"windows": ["IDA: license dialog"]}
    assert client._observed_windows == {"IDA: license dialog"}


def test_non_json_and_non_object_stdout_lines_land_in_the_diagnostic_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.stdout.feed("plain text warning from idalib")
    process.stdout.feed_json([1, 2, 3])
    _shutdown(client, process)

    log = list(client._stdout_log)
    assert "plain text warning from idalib" in log
    assert "[1, 2, 3]" in log


def test_stderr_lines_are_retained_for_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, _ = _make_client(tmp_path, monkeypatch)
    process.stderr.feed("Hex-Rays: warning")
    _shutdown(client, process)

    assert "Hex-Rays: warning" in list(client._stderr_log)
    diagnostics = client._diagnostics()
    assert diagnostics["pid"] == 4321
    assert diagnostics["message_capacity"] == 1_024


def test_close_sends_the_close_command_once_and_waits_for_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, reaped = _make_client(tmp_path, monkeypatch)
    commands: list[str] = []

    def responder(request: JsonObject) -> None:
        commands.append(request["command"])
        process.exit_code = 0
        process.reply_ok(request, {})

    process.responder = responder
    try:
        client.close(timeout=5.0)
        client.close(timeout=5.0)
    finally:
        _shutdown(client, process)

    assert commands == ["close"], "the second close must be a no-op"
    assert process.stdin.closed is True
    assert process.wait_calls == 1
    assert reaped == []


def test_close_on_an_already_dead_worker_skips_the_pipe_entirely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, reaped = _make_client(tmp_path, monkeypatch)
    process.exit_code = 0
    sent: list[JsonObject] = []
    process.responder = sent.append
    try:
        client.close(timeout=5.0)
    finally:
        _shutdown(client, process)

    assert sent == []
    assert process.stdin.closed is True
    assert reaped == []


def test_a_worker_that_ignores_close_is_reaped_after_the_grace_period(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, reaped = _make_client(tmp_path, monkeypatch)
    process.responder = lambda request: process.reply_ok(request, {})
    try:
        client.close(timeout=0.5)
    finally:
        _shutdown(client, process)

    assert reaped == [process], "wait() timing out must escalate to the tree kill"


def test_terminate_reaps_the_whole_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, process, reaped = _make_client(tmp_path, monkeypatch)
    try:
        client.terminate()
    finally:
        _shutdown(client, process)

    assert reaped == [process]
    assert client._closed is True


def test_a_non_dict_error_payload_parses_to_a_protocol_error() -> None:
    error = IdaWorkerError.from_payload("garbage")
    assert error.code == "worker_protocol_error"
    assert error.retryable is False


def test_read_stdout_survives_a_stream_that_only_holds_garbage() -> None:
    client = IdaWorkerClient.__new__(IdaWorkerClient)
    client._messages = queue.Queue(maxsize=8)
    client._message_overflow = Event()
    client._messages_dropped = 0
    client._stdout_log = deque(maxlen=100)

    client._read_stdout(io.StringIO("not json\n{}\n"))

    assert client._messages.get_nowait() == {}
    assert client._messages.get_nowait() is None, "EOF must enqueue the death sentinel"
    assert "not json" in list(client._stdout_log)
