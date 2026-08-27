"""The platform and failure edges of core/limits the eviction tests skip.

``test_core_limits_eviction`` forces the POSIX arm of the memory probe and
drives the happy paths of the directory helpers. What is left uncovered is the
Windows ``GlobalMemoryStatusEx`` arm and the three ``OSError`` fall-throughs
that keep an unreadable capture directory from taking the service down. These
run on any host: the Windows arm is driven through a fake ``ctypes`` so the
same assertions hold on Linux CI, and the failures are injected with
monkeypatch rather than by arranging a genuinely unreadable path.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from headless_re_mcp.core import limits


# --------------------------------------------------------------------------- #
# available_memory_bytes: the Windows arm                                     #
# --------------------------------------------------------------------------- #
class _FakeKernel32:
    def __init__(self, avail_phys: int, *, ok: bool = True) -> None:
        self._avail_phys = avail_phys
        self._ok = ok

    def GlobalMemoryStatusEx(self, status: object) -> int:
        # Our fake byref hands the real MEMORYSTATUSEX struct straight through,
        # so the probe reads back exactly what the "API" wrote.
        status.ullAvailPhys = self._avail_phys  # type: ignore[attr-defined]
        return 1 if self._ok else 0


class _FakeCtypes:
    def __init__(self, kernel32: _FakeKernel32) -> None:
        self.windll = type("_Windll", (), {"kernel32": kernel32})()

    def sizeof(self, _obj: object) -> int:
        return 64

    def byref(self, obj: object) -> object:
        return obj


def test_windows_probe_reports_available_physical_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(limits, "ctypes", _FakeCtypes(_FakeKernel32(2048)))
    assert limits.available_memory_bytes() == 2048


def test_windows_probe_returns_none_when_the_api_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A zero return from GlobalMemoryStatusEx is "could not read", which must
    # degrade to None so the caller allows the work rather than refusing it.
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(limits, "ctypes", _FakeCtypes(_FakeKernel32(0, ok=False)))
    assert limits.available_memory_bytes() is None


# --------------------------------------------------------------------------- #
# prune_capped_dir: an unreadable directory is a no-op, not a crash           #
# --------------------------------------------------------------------------- #
def test_prune_returns_zero_when_the_directory_cannot_be_listed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = tmp_path / "captures"
    directory.mkdir()
    real_iterdir = Path.iterdir

    def denied(self: Path):  # type: ignore[no-untyped-def]
        if self == directory:
            raise OSError("permission denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", denied)
    assert limits.prune_capped_dir(directory, max_entries=1, max_bytes=1) == 0


# --------------------------------------------------------------------------- #
# _dir_size: keep summing past a bad child, bail out on a broken walk         #
# --------------------------------------------------------------------------- #
def test_dir_size_skips_a_child_whose_stat_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.bin").write_bytes(b"x" * 10)
    # is_file() would normally swallow the stat error itself; force it True so
    # the size read is what raises and the loop's own except is exercised.
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    real_stat = Path.stat

    def boom(self: Path, *, follow_symlinks: bool = True):  # type: ignore[no-untyped-def]
        if self.name == "a.bin":
            raise OSError("vanished mid-walk")
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", boom)
    assert limits._dir_size(tree) == 0


def test_dir_size_returns_what_it_has_when_the_walk_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()

    def broken_walk(self: Path, pattern: str):  # type: ignore[no-untyped-def]
        raise OSError("walk failed")

    monkeypatch.setattr(Path, "rglob", broken_walk)
    assert limits._dir_size(tree) == 0
