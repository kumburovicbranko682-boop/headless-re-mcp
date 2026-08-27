"""The IDA worker request deadline is bounded at the client boundary.

``IdaWorkerClient.request`` fed the caller's ``timeout`` straight into
``_receive``, which turns it into ``deadline = started + timeout`` and stops
only when ``remaining <= 0``. A NaN makes that comparison always false, so the
receive loop polls forever -- holding the single request lock against a worker
that never answers -- and a huge value lets a wedged Hex-Rays call hold that
lock for as long as the caller named. The MCP schema bounds this (decompile is
le=600, the rest le=300), but the agent transport invokes handlers from raw
model arguments with no schema check, the same gap ``clamp_cli_timeout`` closes
for the CLI adapters. request() now clamps first, before it ever touches the
worker.
"""

from __future__ import annotations

import io
import json
import math
import queue
from pathlib import Path
from typing import Any

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
    client._stdout_thread.join(timeout=1.0)
    while True:
        try:
            client._messages.get_nowait()
        except queue.Empty:
            break
    return client


def test_request_rejects_a_nonfinite_or_nonpositive_timeout_before_the_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NaN/zero/negative is invalid_params, refused before anything is sent.

    NaN is the load-bearing case: it slips past ``remaining <= 0`` in _receive
    and defeats the deadline outright. The empty stdin proves the guard fires
    before the request is ever written to the worker.
    """
    client = _make_client(tmp_path, monkeypatch)

    def _must_not_receive(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("_receive ran for a rejected timeout")

    monkeypatch.setattr(client, "_receive", _must_not_receive)

    for bad in (math.nan, 0.0, -1.0, -600.0):
        with pytest.raises(IdaWorkerError) as caught:
            client.request("noop", timeout=bad)
        assert caught.value.code == "invalid_params"
    assert client._process.stdin.getvalue() == ""


def test_request_caps_a_huge_timeout_to_the_schema_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A value over the ceiling is capped; an in-range value passes through."""
    client = _make_client(tmp_path, monkeypatch)
    seen: list[float] = []

    def _record(predicate: Any, timeout: float, **kwargs: Any) -> dict[str, Any]:
        seen.append(timeout)
        return {"ok": True, "data": {"echo": True}}

    monkeypatch.setattr(client, "_receive", _record)

    assert client.request("noop", timeout=10**9) == {"echo": True}
    assert client.request("noop", timeout=42.0) == {"echo": True}
    assert seen == [client_module._MAX_REQUEST_TIMEOUT_S, 42.0]
