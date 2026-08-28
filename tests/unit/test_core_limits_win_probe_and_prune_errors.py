"""The two edges core/limits leaves for the platform and the filesystem.

test_core_limits_eviction pins the POSIX memory probe, the eviction loop and the
deletion helpers, but two arms never run under Linux CI: the Windows branch of
available_memory_bytes (GlobalMemoryStatusEx), and prune_capped_dir degrading to
"removed nothing" when the capture directory itself cannot be listed. Both are
honesty edges -- a failed Windows query must say "don't guess" rather than claim
zero free, and an unreadable directory must be a no-op rather than a crash in the
retention path -- so this drives each with a faked ctypes surface and a directory
whose iterdir() raises.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from headless_re_mcp.core import limits


class _FakeStatus:
    """Stand-in for _MemoryStatusEx: a plain object the fake ctypes can size."""

    def __init__(self) -> None:
        self.dwLength = 0
        self.ullAvailPhys = 987_654_321


def _fake_ctypes(query_result: int) -> types.SimpleNamespace:
    """A ctypes shim whose GlobalMemoryStatusEx returns ``query_result``."""
    kernel32 = types.SimpleNamespace(GlobalMemoryStatusEx=lambda ref: query_result)
    return types.SimpleNamespace(
        sizeof=lambda obj: 64,
        byref=lambda obj: obj,
        windll=types.SimpleNamespace(kernel32=kernel32),
    )


def test_win32_probe_reports_available_physical_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows a successful query returns ullAvailPhys, not a guess."""
    monkeypatch.setattr(limits.sys, "platform", "win32")
    monkeypatch.setattr(limits, "_MemoryStatusEx", _FakeStatus)
    monkeypatch.setattr(limits, "ctypes", _fake_ctypes(query_result=1))
    assert limits.available_memory_bytes() == 987_654_321


def test_win32_probe_returns_none_when_the_query_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero return from GlobalMemoryStatusEx is unknown, so refuse to guess.

    None is the contract that tells callers to allow the work rather than treat
    a failed probe as "no memory free" and refuse a job the machine could run.
    """
    monkeypatch.setattr(limits.sys, "platform", "win32")
    monkeypatch.setattr(limits, "_MemoryStatusEx", _FakeStatus)
    monkeypatch.setattr(limits, "ctypes", _fake_ctypes(query_result=0))
    assert limits.available_memory_bytes() is None


class _UnlistableDir:
    """A directory that exists but whose contents cannot be enumerated."""

    def is_dir(self) -> bool:
        return True

    def iterdir(self) -> list[Path]:
        raise OSError("permission denied")


def test_prune_reports_nothing_removed_when_the_directory_cannot_be_listed() -> None:
    """A capture dir that raises on iterdir must be a no-op, not a crash.

    prune runs on the retention path; if listing the directory fails it has to
    fall through to "removed 0" so a single unreadable capture tree cannot take
    down the walk.
    """
    assert limits.prune_capped_dir(_UnlistableDir(), max_entries=1, max_bytes=1) == 0  # type: ignore[arg-type]
