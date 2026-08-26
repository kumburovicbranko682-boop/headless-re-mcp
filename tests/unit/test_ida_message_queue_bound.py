from __future__ import annotations

import io
import json
import queue
from pathlib import Path

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
        Settings(ida_home=tmp_path, artifact_root=tmp_path / "artifacts"),
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
