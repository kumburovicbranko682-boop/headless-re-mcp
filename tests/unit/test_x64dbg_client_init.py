"""Coverage for ``XdbgClient.__init__`` spawn/connect wiring.

The constructor resolves the executable, checks its architecture, spawns x64dbg
(either directly or on a hidden desktop), starts the log/window monitor threads,
and completes the RPC handshake -- tearing everything down if the handshake
fails. None of that can run against a real x64dbg on a Linux runner, so these
tests stub the process, the monitor threads, and the transport handshake to walk
the direct-spawn, hidden-desktop, and failure-teardown branches.
"""

from __future__ import annotations

import subprocess
from io import StringIO
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.x64dbg import client
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.models import Architecture


class _FakePopen:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.pid = 4242
        self.stdout = StringIO()
        self.stderr = StringIO()
        self.stdin = StringIO()
        self.returncode: int | None = None

    def poll(self) -> Any:
        return None


class _FakeThread:
    def __init__(
        self, *, target: Any = None, args: Any = (), name: str = "", daemon: bool = False
    ) -> None:
        self.target = target
        self.args = args
        self.started = False

    def start(self) -> None:
        self.started = True


class _FakeDesktop:
    def __init__(self) -> None:
        self.spawned: Any = None

    def spawn(self, argv: Any, *, environment: Any, encoding: str, errors: str) -> _FakePopen:
        self.spawned = argv
        return _FakePopen()


class _FakeJob:
    def __init__(self) -> None:
        self.assigned: list[int] = []

    def assign(self, pid: int) -> None:
        self.assigned.append(pid)


def _patch_common(monkeypatch: pytest.MonkeyPatch, *, hello: Any) -> None:
    monkeypatch.setattr(client, "detect_pe_architecture", lambda p: Architecture.X64)
    monkeypatch.setattr(client, "no_window_popen_kwargs", lambda: {})
    monkeypatch.setattr(client, "assign_to_process_group", lambda pid: None)
    monkeypatch.setattr(client, "Thread", _FakeThread)
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(XdbgClient, "_connect_transport", lambda self, timeout: hello)
    monkeypatch.setattr(XdbgClient, "desktop_snapshot", lambda self: {"windows": []})
    monkeypatch.setattr(XdbgClient, "_observe_windows", lambda self: None)


def test_init_rejects_architecture_mismatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    exe = tmp_path / "x64dbg.exe"
    exe.write_text("x")
    monkeypatch.setattr(client, "detect_pe_architecture", lambda p: Architecture.X86)
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient(exe, Architecture.X64)
    assert exc.value.code == "architecture_mismatch"


def test_init_direct_spawn_connects(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    exe = tmp_path / "x64dbg.exe"
    exe.write_text("x")
    _patch_common(monkeypatch, hello={"capabilities": ["read", "write"], "worker": "w1"})
    inst = XdbgClient(exe, Architecture.X64)
    try:
        assert inst._capabilities == frozenset({"read", "write"})
        assert inst._metadata["worker"] == "w1"
        assert inst._metadata["desktop"] == {"windows": []}
        assert inst._process.pid == 4242
        assert inst._desktop is None  # direct spawn, no hidden desktop
        assert cast(Any, inst._stdout_thread).started
        assert cast(Any, inst._window_thread).started
    finally:
        inst._user_directory.cleanup()


def test_init_hidden_desktop_assigns_job(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    exe = tmp_path / "x64dbg.exe"
    exe.write_text("x")
    _patch_common(monkeypatch, hello={"capabilities": []})
    desktop = _FakeDesktop()
    job = _FakeJob()
    monkeypatch.setattr(client, "HiddenDesktop", SimpleNamespace(create=lambda prefix: desktop))
    monkeypatch.setattr(client, "DesktopIsolationJob", SimpleNamespace(create=lambda: job))
    inst = XdbgClient(exe, Architecture.X64, hidden_desktop=True)
    try:
        assert cast(Any, inst._desktop) is desktop
        assert job.assigned == [4242]  # isolation job bound to the spawned pid
        assert desktop.spawned[0] == str(exe.resolve())
    finally:
        inst._user_directory.cleanup()


def test_init_hidden_desktop_without_isolation_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    exe = tmp_path / "x64dbg.exe"
    exe.write_text("x")
    _patch_common(monkeypatch, hello={"capabilities": []})
    desktop = _FakeDesktop()
    monkeypatch.setattr(client, "HiddenDesktop", SimpleNamespace(create=lambda prefix: desktop))
    monkeypatch.setattr(client, "DesktopIsolationJob", SimpleNamespace(create=lambda: None))
    inst = XdbgClient(exe, Architecture.X64, hidden_desktop=True)
    try:
        assert inst._isolation_job is None  # create() returned None -> no assign
    finally:
        inst._user_directory.cleanup()


def test_init_rejects_non_list_capabilities_and_tears_down(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    exe = tmp_path / "x64dbg.exe"
    exe.write_text("x")
    _patch_common(monkeypatch, hello={"capabilities": "not-a-list"})
    terminated: list[bool] = []
    monkeypatch.setattr(XdbgClient, "terminate", lambda self: terminated.append(True))
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient(exe, Architecture.X64)
    assert exc.value.code == "rpc_protocol_error"
    assert terminated == [True]  # constructor cleaned up on the failed handshake


def test_init_tears_down_when_handshake_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    exe = tmp_path / "x64dbg.exe"
    exe.write_text("x")
    _patch_common(monkeypatch, hello={"capabilities": []})

    def boom(self: XdbgClient, timeout: float) -> Any:
        raise XdbgRpcError("rpc_startup_timeout", "no worker")

    monkeypatch.setattr(XdbgClient, "_connect_transport", boom)
    terminated: list[bool] = []
    monkeypatch.setattr(XdbgClient, "terminate", lambda self: terminated.append(True))
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient(exe, Architecture.X64)
    assert exc.value.code == "rpc_startup_timeout"
    assert terminated == [True]
