from __future__ import annotations

import io
import json
import queue
from collections import deque
from pathlib import Path
from threading import Event

import pytest

import headless_re_mcp.backends.ida.client as client_module
from headless_re_mcp.backends.ida.client import IdaWorkerClient
from headless_re_mcp.config import Settings


class _Process:
    pid = 4321

    def __init__(self) -> None:
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(
            json.dumps({"event": "ready", "data": {"capabilities": []}}) + "\n"
        )
        self.stderr = io.StringIO()

    def poll(self) -> None:
        return None


def test_ida_stdout_messages_are_bounded_when_no_request_is_receiving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A noisy worker queued every JSON line while no request consumed stdout.

    Measured with 5,000 messages: all 5,000 remained resident. A malformed or
    runaway worker can therefore grow the service heap for its whole lifetime.
    """
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(client_module.subprocess, "Popen", lambda *args, **kwargs: _Process())
    monkeypatch.setattr(client_module, "assign_to_process_group", lambda pid: None)
    monkeypatch.setattr(client_module, "describe_process_windows", lambda pid: [])
    client = IdaWorkerClient(
        binary,
        Settings(
            ida_home=tmp_path,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        ),
        startup_timeout=1.0,
    )
    client._stdout_thread.join(timeout=1.0)
    while True:
        try:
            client._messages.get_nowait()
        except queue.Empty:
            break

    stream = io.StringIO(
        "".join(json.dumps({"event": "noise", "index": index}) + "\n" for index in range(5_000))
    )
    client._read_stdout(stream)

    assert client._messages.maxsize == 1_024
    assert client._messages.qsize() <= 1_024
    assert client._message_overflow.is_set()


def test_ida_stdout_rejects_one_oversized_protocol_line() -> None:
    """The queue count bound still admitted an arbitrarily large JSON object.

    A single 2,000,000-character field remained live in one queue slot, so a
    small message count did not provide a byte bound.
    """
    client = object.__new__(IdaWorkerClient)
    client._messages = queue.Queue(maxsize=1_024)
    client._message_overflow = Event()
    client._messages_dropped = 0
    client._stdout_log = deque(maxlen=100)
    stream = io.StringIO(json.dumps({"event": "noise", "blob": "x" * 2_000_000}) + "\n")

    client._read_stdout(stream)

    assert client._message_overflow.is_set()
    assert client._messages_dropped == 1
    assert client._messages.qsize() == 1  # EOF sentinel only; the oversized object was dropped.


def test_ida_stderr_bounds_each_retained_diagnostic_line() -> None:
    """The 100-entry stderr deque retained 10,000,000 characters.

    Line count alone does not bound memory when a worker writes very long
    diagnostics or writes forever without a newline.
    """
    client = object.__new__(IdaWorkerClient)
    client._stderr_log = deque(maxlen=100)
    stream = io.StringIO(("x" * 100_000 + "\n") * 150)

    client._read_stderr(stream)

    assert len(client._stderr_log) == 100
    assert max(map(len, client._stderr_log)) <= 8_192
    assert sum(map(len, client._stderr_log)) <= 100 * 8_192
    assert all(line.endswith("[truncated]") for line in client._stderr_log)
