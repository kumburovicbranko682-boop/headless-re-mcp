"""A noisy IDA worker must not grow the service heap without bound.

The stdout reader used to ``put`` every unsolicited JSON line onto an unbounded
queue, so a worker emitting thousands of messages while no request was draining
left them all resident. The queue now has a fixed capacity, and the overflow is
surfaced to the next receive as ``worker_output_overflow`` instead of silently
accumulating.
"""

from __future__ import annotations

import io
import json
import queue
from pathlib import Path

import pytest

import headless_re_mcp.backends.ida.client as client_module
from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError
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


def _make_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IdaWorkerClient:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(client_module.subprocess, "Popen", lambda *a, **k: _Process())
    monkeypatch.setattr(client_module, "assign_to_process_group", lambda pid: None)
    monkeypatch.setattr(client_module, "describe_process_windows", lambda pid: [])
    settings = Settings(
        ida_home=tmp_path,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    client = IdaWorkerClient(binary, settings, startup_timeout=1.0)
    # Let the startup reader thread drain its stub stdout, then clear the queue
    # so the flood below starts from an empty, idle queue.
    client._stdout_thread.join(timeout=1.0)
    while True:
        try:
            client._messages.get_nowait()
        except queue.Empty:
            break
    return client


def test_ida_stdout_messages_are_bounded_when_no_request_is_receiving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client(tmp_path, monkeypatch)

    stream = io.StringIO(
        "".join(
            json.dumps({"event": "noise", "index": index}) + "\n"
            for index in range(5_000)
        )
    )
    client._read_stdout(stream)

    assert client._messages.maxsize == 1_024
    assert client._messages.qsize() <= 1_024
    assert client._message_overflow.is_set()
    assert client._messages_dropped > 0


def test_overflow_surfaces_as_worker_output_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client(tmp_path, monkeypatch)
    client._message_overflow.set()

    with pytest.raises(IdaWorkerError) as caught:
        client._receive(lambda item: True, timeout=1.0)

    assert caught.value.code == "worker_output_overflow"
    details = caught.value.details
    assert details["message_capacity"] == 1_024
