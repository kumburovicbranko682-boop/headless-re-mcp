"""The remaining guard arcs of the shared bounding helpers in core/limits.

test_core_limits_eviction pins the POSIX memory probe, the eviction loop and
the deletion helpers. This file reaches the arms that only fire on Windows or
on a filesystem that fails mid-walk: the Win32 GlobalMemoryStatusEx branch
(driven through a faked ``ctypes.windll`` so it runs on Linux too), the prune
that cannot list its directory, and ``_dir_size`` skipping a file it cannot
stat and bailing out when the walk itself raises. Every test is deterministic
-- no timing, no threads -- and drives the helpers directly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core import limits


# --------------------------------------------------------------------------- #
# available_memory_bytes: the Win32 arm                                       #
# --------------------------------------------------------------------------- #
def test_available_memory_reads_the_win32_status_struct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows the free byte count comes from GlobalMemoryStatusEx."""
    monkeypatch.setattr(sys, "platform", "win32")

    class _Kernel32:
        def GlobalMemoryStatusEx(self, ref: Any) -> int:
            ref._obj.ullAvailPhys = 8192
            return 1

    class _Windll:
        kernel32 = _Kernel32()

    monkeypatch.setattr(limits.ctypes, "windll", _Windll(), raising=False)
    assert limits.available_memory_bytes() == 8192


def test_available_memory_returns_none_when_the_win32_probe_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")

    class _Kernel32:
        def GlobalMemoryStatusEx(self, ref: Any) -> int:
            return 0

    class _Windll:
        kernel32 = _Kernel32()

    monkeypatch.setattr(limits.ctypes, "windll", _Windll(), raising=False)
    assert limits.available_memory_bytes() is None


# --------------------------------------------------------------------------- #
# prune_capped_dir: the directory cannot be listed                            #
# --------------------------------------------------------------------------- #
def test_prune_returns_zero_when_the_directory_cannot_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    real_iterdir = Path.iterdir

    def flaky_iterdir(self: Path) -> Any:
        if self == root:
            raise OSError("listing denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", flaky_iterdir)
    assert limits.prune_capped_dir(root, max_entries=1, max_bytes=1) == 0


# --------------------------------------------------------------------------- #
# _dir_size: mid-walk failures                                                #
# --------------------------------------------------------------------------- #
def test_dir_size_skips_a_file_it_cannot_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file whose size probe fails after is_file() passed is skipped, not fatal."""
    sub = tmp_path / "tree"
    sub.mkdir()
    (sub / "a.bin").write_bytes(b"x" * 10)
    (sub / "b.bin").write_bytes(b"x" * 20)
    real_stat = Path.stat
    calls: dict[str, int] = {}

    def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "a.bin":
            calls[self.name] = calls.get(self.name, 0) + 1
            if calls[self.name] >= 2:
                raise OSError("stat denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    assert limits._dir_size(sub) == 20


def test_dir_size_returns_what_it_has_when_the_walk_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sub = tmp_path / "tree"
    sub.mkdir()

    def boom_rglob(self: Path, pattern: str) -> Any:
        raise OSError("walk denied")

    monkeypatch.setattr(Path, "rglob", boom_rglob)
    assert limits._dir_size(sub) == 0
