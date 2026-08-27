"""Cross-platform branches of the managed-subprocess mixin.

The descendant-killing behaviour that only a real Win32 process tree can prove
is pinned in ``test_managed_subprocess_terminate.py`` and skipped off Windows.
This file covers the parts that run anywhere: the no-window kwargs on a POSIX
host, the pid and window-observation accessors, and that terminate delegates to
the tree-killer under whatever lock the client carries. These back the IDA and
x64dbg clients, so a regression here strands analyzer processes.
"""

from __future__ import annotations

import os
import threading
from typing import Any

import pytest

from headless_re_mcp.backends.common import subprocess_rpc
from headless_re_mcp.backends.common.subprocess_rpc import (
    ManagedSubprocessMixin,
    no_window_popen_kwargs,
)


class _FakeProcess:
    def __init__(self, pid: int = 4321) -> None:
        self.pid = pid


class _Managed(ManagedSubprocessMixin):
    def __init__(self, process: Any, *, lock: Any = None) -> None:
        self._process = process
        self._observed_windows: set[str] = set()
        if lock is not None:
            self._lock = lock


@pytest.mark.skipif(os.name == "nt", reason="POSIX path of the window suppressor")
def test_no_window_kwargs_are_inert_on_posix() -> None:
    """Off Windows there is no console to hide, so the kwargs are no-ops."""
    kwargs = no_window_popen_kwargs()
    assert kwargs == {"creationflags": 0, "startupinfo": None}


def test_pid_reads_through_to_the_underlying_process() -> None:
    managed = _Managed(_FakeProcess(pid=9090))
    assert managed.pid == 9090


def test_analyzer_windows_returns_sorted_titles_and_remembers_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The accessor sorts what the OS reports and records every title it saw.

    ``_observed_windows`` is how a client later proves an analyzer window
    appeared even after it closed; the accessor must fold each sighting in, not
    just return the current set.
    """
    monkeypatch.setattr(
        subprocess_rpc, "describe_process_windows", lambda pid: {"IDA v9", "About"}
    )
    managed = _Managed(_FakeProcess())

    titles = managed.analyzer_windows

    assert titles == ("About", "IDA v9")
    assert managed._observed_windows == {"About", "IDA v9"}


def test_terminate_delegates_to_the_tree_killer_under_the_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminate must kill the whole tree, holding the client's lock if it has one."""
    calls: list[tuple[Any, float]] = []

    def fake_kill(process: Any, *, wait_s: float) -> None:
        calls.append((process, wait_s))

    monkeypatch.setattr(subprocess_rpc, "terminate_process_tree", fake_kill)
    process = _FakeProcess()
    lock = threading.Lock()
    managed = _Managed(process, lock=lock)

    managed.terminate_process(wait_timeout=1.5)

    assert calls == [(process, 1.5)]


def test_terminate_uses_a_null_lock_when_the_client_has_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client that never set a lock still terminates, via the null context."""
    seen: list[Any] = []
    monkeypatch.setattr(
        subprocess_rpc,
        "terminate_process_tree",
        lambda process, *, wait_s: seen.append(process),
    )
    process = _FakeProcess()
    managed = _Managed(process)  # no _lock attribute at all

    managed.terminate_process()

    assert seen == [process]


def test_pid_is_always_a_plain_int() -> None:
    """The accessor coerces to int so callers never see a raw driver type."""

    class _Weird:
        pid = "777"

    assert _Managed(_Weird()).pid == 777
