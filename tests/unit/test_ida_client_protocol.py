"""Client-side protocol handling for the IDA worker, driven without a real worker.

``IdaWorkerClient`` launches an idalib worker subprocess in ``__init__``, so on a
host without IDA its request/response machinery -- startup handshake, deadline
receive loop, output readers, and the close/terminate paths -- never runs. These
tests fake the subprocess with in-memory streams and drive each method directly,
so the decisions that keep a wedged or misbehaving worker from corrupting a
session are exercised: a fatal handshake is surfaced, a timed-out or overflowing
receive retires the worker, a non-object response is rejected, and malformed
worker output is logged rather than fed into the protocol.
"""

from __future__ import annotations

import io
import json
import queue
import subprocess
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ida.client as client_module
from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError
from headless_re_mcp.config import Settings

_READY = json.dumps({"event": "ready", "data": {"capabilities": ["decompile"], "arch": "x64"}})


class _FakeProc:
    def __init__(self, stdout_text: str, *, poll_value: int | None = None) -> None:
        self.pid = 4321
        self.stdin: Any = io.StringIO()
        self.stdout = io.StringIO(stdout_text)
        self.stderr = io.StringIO()
        self._poll = poll_value
        self.wait_raises = False
        self.waited = False

    def poll(self) -> int | None:
        return self._poll

    def wait(self, timeout: float = 0.0) -> int:
        self.waited = True
        if self.wait_raises:
            raise subprocess.TimeoutExpired(cmd="ida", timeout=timeout)
        return 0


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=tmp_path,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch, proc: _FakeProc, *, killed: list[int] | None = None
) -> None:
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(client_module, "assign_to_process_group", lambda pid: None)
    monkeypatch.setattr(client_module, "describe_process_windows", lambda pid: [])
    recorded = killed if killed is not None else []
    monkeypatch.setattr(
        client_module, "terminate_process_tree", lambda proc, **k: recorded.append(proc.pid)
    )


def _make_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout_text: str = _READY + "\n",
) -> IdaWorkerClient:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    proc = _FakeProc(stdout_text)
    _install_fakes(monkeypatch, proc)
    client = IdaWorkerClient(binary, _settings(tmp_path), startup_timeout=1.0)
    client._stdout_thread.join(timeout=1.0)
    client._stderr_thread.join(timeout=1.0)
    _drain(client)
    return client


def _drain(client: IdaWorkerClient) -> None:
    while True:
        try:
            client._messages.get_nowait()
        except queue.Empty:
            break


# --- from_payload and construction guards -----------------------------------


def test_from_payload_rejects_a_non_dict() -> None:
    error = IdaWorkerError.from_payload("not a dict")
    assert error.code == "worker_protocol_error"


def test_construction_without_ida_home_is_backend_unavailable(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    settings = _settings(tmp_path)
    object.__setattr__(settings, "ida_home", None)
    with pytest.raises(IdaWorkerError) as caught:
        IdaWorkerClient(binary, settings)
    assert caught.value.code == "backend_unavailable"


# --- startup handshake variants ---------------------------------------------


def test_startup_fatal_event_is_surfaced_and_worker_terminated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fatal = json.dumps({"event": "fatal", "error": {"code": "boom", "message": "kaboom"}})
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    killed: list[int] = []
    proc = _FakeProc(fatal + "\n")
    _install_fakes(monkeypatch, proc, killed=killed)
    with pytest.raises(IdaWorkerError) as caught:
        IdaWorkerClient(binary, _settings(tmp_path), startup_timeout=1.0)
    assert caught.value.code == "boom"
    assert killed == [4321]


def test_startup_ready_without_data_object_is_a_protocol_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    killed: list[int] = []
    proc = _FakeProc(json.dumps({"event": "ready"}) + "\n")
    _install_fakes(monkeypatch, proc, killed=killed)
    with pytest.raises(IdaWorkerError) as caught:
        IdaWorkerClient(binary, _settings(tmp_path), startup_timeout=1.0)
    assert caught.value.code == "worker_protocol_error"
    assert killed == [4321]


def test_startup_ignores_non_list_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = json.dumps({"event": "ready", "data": {"capabilities": "nope"}})
    client = _make_client(tmp_path, monkeypatch, stdout_text=ready + "\n")
    assert client.capabilities == frozenset()


# --- properties on a healthy client -----------------------------------------


def test_healthy_client_exposes_metadata_and_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    assert client.pid == 4321
    assert client.exit_code is None
    assert client.capabilities == frozenset({"decompile"})
    assert client.metadata == {"capabilities": ["decompile"], "arch": "x64"}
    assert client.analyzer_windows == ()


# --- request() decision branches --------------------------------------------


def test_request_on_a_closed_client_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._closed = True
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "session_closed"


def test_request_when_the_worker_has_exited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._process._poll = 9  # type: ignore[attr-defined]
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "worker_exited"


def test_request_maps_a_broken_stdin_pipe_to_worker_exited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)

    class _BrokenStdin:
        def write(self, _data: str) -> int:
            raise BrokenPipeError("gone")

        def flush(self) -> None:
            pass

    client._process.stdin = _BrokenStdin()  # type: ignore[assignment]
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "worker_exited"


def test_request_retires_the_worker_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timed-out worker is still inside Hex-Rays and cannot serve the next call."""
    client = _make_client(tmp_path, monkeypatch)
    terminated: list[bool] = []
    monkeypatch.setattr(client, "terminate", lambda: terminated.append(True))

    def _timeout(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise IdaWorkerError("worker_timeout", "no answer", retryable=True)

    monkeypatch.setattr(client, "_receive", _timeout)
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "worker_timeout"
    assert terminated == [True]


def test_request_does_not_retire_the_worker_on_an_ordinary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backend error that is not a timeout/overflow re-raises without a kill."""
    client = _make_client(tmp_path, monkeypatch)
    terminated: list[bool] = []
    monkeypatch.setattr(client, "terminate", lambda: terminated.append(True))

    def _fail(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise IdaWorkerError("backend_error", "boom")

    monkeypatch.setattr(client, "_receive", _fail)
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "backend_error"
    assert terminated == []


def test_request_rejects_a_not_ok_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(
        client, "_receive", lambda *a, **k: {"ok": False, "error": {"code": "nope"}}
    )
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "nope"


def test_request_rejects_a_response_without_a_data_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(client, "_receive", lambda *a, **k: {"ok": True, "data": "flat"})
    with pytest.raises(IdaWorkerError) as caught:
        client.request("noop")
    assert caught.value.code == "worker_protocol_error"


def test_request_returns_the_data_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(client, "_receive", lambda *a, **k: {"ok": True, "data": {"x": 1}})
    assert client.request("noop") == {"x": 1}


# --- close() and terminate() ------------------------------------------------


def test_close_sends_close_then_waits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(client, "_receive", lambda *a, **k: {"ok": True, "data": {}})
    client.close(timeout=1.0)
    assert client._closed is True
    assert client._process.waited is True  # type: ignore[attr-defined]


def test_close_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._closed = True
    client.close()  # returns immediately without touching the process
    assert client._process.waited is False  # type: ignore[attr-defined]


def test_close_terminates_when_wait_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(client, "_receive", lambda *a, **k: {"ok": True, "data": {}})
    client._process.wait_raises = True  # type: ignore[attr-defined]
    terminated: list[bool] = []
    monkeypatch.setattr(client, "terminate", lambda: terminated.append(True))
    client.close(timeout=0.1)
    assert terminated == [True]


def test_close_skips_the_close_request_when_the_worker_already_exited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exited worker gets no close request, but the streams still get cleaned up."""
    client = _make_client(tmp_path, monkeypatch)
    client._process._poll = 0  # type: ignore[attr-defined]

    def _must_not_receive(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise AssertionError("close must not talk to an exited worker")

    monkeypatch.setattr(client, "_receive", _must_not_receive)
    client._process.stdin = None
    client.close(timeout=0.1)
    assert client._closed is True
    assert client._process.waited is True  # type: ignore[attr-defined]


def test_terminate_marks_closed_and_kills_the_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    killed: list[int] = []
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(
        client_module, "terminate_process_tree", lambda p, **k: killed.append(p.pid)
    )
    client.terminate()
    assert client._closed is True
    assert killed == [4321]


# --- output readers ---------------------------------------------------------


def test_read_stdout_enqueues_objects_and_logs_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only JSON objects are protocol messages; scalars and garbage are logged."""
    client = _make_client(tmp_path, monkeypatch)
    client._stdout_log.clear()
    stream = io.StringIO('{"id": 1, "ok": true}\n123\nnot json\n')
    client._read_stdout(stream)
    first = client._messages.get_nowait()
    assert first == {"id": 1, "ok": True}
    assert client._messages.get_nowait() is None  # sentinel from the finally
    assert "123" in client._stdout_log
    assert "not json" in client._stdout_log


def test_read_stderr_logs_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._stderr_log.clear()
    client._read_stderr(io.StringIO("first\nsecond\n"))
    assert list(client._stderr_log) == ["first", "second"]


# --- _receive() deadline loop -----------------------------------------------


def test_receive_slides_past_progress_and_logs_stray_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._stdout_log.clear()
    client._messages.put({"event": "progress", "pct": 10})
    client._messages.put({"event": "info", "note": "stray"})
    client._messages.put({"id": 7, "ok": True, "data": {}})
    message = client._receive(lambda item: item.get("id") == 7, 5.0, extend_on_progress=True)
    assert message["id"] == 7
    assert any("stray" in line for line in client._stdout_log)


def test_receive_times_out_after_polling_an_empty_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the worker alive but silent, the loop polls then times out."""
    client = _make_client(tmp_path, monkeypatch)
    with pytest.raises(IdaWorkerError) as caught:
        client._receive(lambda item: False, 0.08)
    assert caught.value.code == "worker_timeout"


def test_receive_reports_exit_when_the_queue_drains_to_a_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._messages.put(None)
    with pytest.raises(IdaWorkerError) as caught:
        client._receive(lambda item: True, 5.0)
    assert caught.value.code == "worker_exited"


def test_receive_reports_exit_when_the_worker_died_mid_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._process._poll = 2  # type: ignore[attr-defined]
    with pytest.raises(IdaWorkerError) as caught:
        client._receive(lambda item: False, 5.0)
    assert caught.value.code == "worker_exited"


def test_receive_surfaces_message_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._message_overflow.set()
    with pytest.raises(IdaWorkerError) as caught:
        client._receive(lambda item: True, 5.0)
    assert caught.value.code == "worker_output_overflow"


# --- _observe_windows() -----------------------------------------------------


def test_observe_windows_refuses_and_does_not_double_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A window up refuses the call every time, but records each title once."""
    client = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(client_module, "describe_process_windows", lambda pid: ["Analyzer"])
    for _ in range(2):
        with pytest.raises(IdaWorkerError) as caught:
            client._observe_windows()
        assert caught.value.code == "analyzer_window_detected"
    assert client._observed_windows == {"Analyzer"}
