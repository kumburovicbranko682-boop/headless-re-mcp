"""Platform and I/O-error edges of core/limits not reachable on the POSIX arm.

test_core_limits_eviction.py forces sys.platform to "linux" so it can run
everywhere, which leaves the Windows GlobalMemoryStatusEx probe unexercised.
It also never drives the defensive OSError arms: an iterdir that fails after
is_dir said yes, and a directory walk that trips on a child mid-flight. These
are the branches that decide, on a machine under stress, whether "how much
memory is free" degrades to "don't guess" and whether an unreadable capture
directory is a quiet no-op instead of a crash. This file pins them by faking
the Windows kernel call and by making the filesystem calls raise.
"""

from __future__ import annotations

import ctypes
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core import limits


# --------------------------------------------------------------------------- #
# available_memory_bytes: the Windows arm                                     #
# --------------------------------------------------------------------------- #
class _FakeKernel32:
    def __init__(self, *, succeed: bool, avail: int) -> None:
        self._succeed = succeed
        self._avail = avail
        self.calls = 0

    def GlobalMemoryStatusEx(self, ref: Any) -> int:  # noqa: N802 - mirrors the Win32 name
        self.calls += 1
        if self._succeed:
            # byref(status)._obj is the very structure the caller allocated, so
            # a real GlobalMemoryStatusEx writing ullAvailPhys is modelled here.
            ref._obj.ullAvailPhys = self._avail
            return 1
        return 0


class _FakeWinDll:
    def __init__(self, kernel32: _FakeKernel32) -> None:
        self.kernel32 = kernel32


def test_windows_probe_returns_available_physical_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = _FakeKernel32(succeed=True, avail=4096)
    monkeypatch.setattr(limits.sys, "platform", "win32")
    monkeypatch.setattr(limits.ctypes, "windll", _FakeWinDll(kernel), raising=False)

    assert limits.available_memory_bytes() == 4096
    assert kernel.calls == 1, "the kernel probe must actually be invoked"


def test_windows_probe_returns_none_when_the_kernel_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A GlobalMemoryStatusEx that returns 0 must degrade to 'don't guess'."""
    kernel = _FakeKernel32(succeed=False, avail=4096)
    monkeypatch.setattr(limits.sys, "platform", "win32")
    monkeypatch.setattr(limits.ctypes, "windll", _FakeWinDll(kernel), raising=False)

    assert limits.available_memory_bytes() is None


def test_the_windows_status_length_is_set_before_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GlobalMemoryStatusEx rejects a struct whose dwLength was not initialised."""
    seen: dict[str, int] = {}

    class _RecordingKernel:
        def GlobalMemoryStatusEx(self, ref: Any) -> int:  # noqa: N802
            seen["dwLength"] = int(ref._obj.dwLength)
            return 1

    monkeypatch.setattr(limits.sys, "platform", "win32")
    monkeypatch.setattr(limits.ctypes, "windll", _FakeWinDll(_RecordingKernel()), raising=False)

    limits.available_memory_bytes()

    assert seen["dwLength"] == ctypes.sizeof(limits._MemoryStatusEx)


# --------------------------------------------------------------------------- #
# prune_capped_dir: iterdir fails after is_dir said yes                       #
# --------------------------------------------------------------------------- #
def test_prune_is_a_noop_when_listing_the_directory_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "captures"
    root.mkdir()
    (root / "e0.bin").write_bytes(b"x")

    def exploding_iterdir(self: Path) -> Any:
        raise OSError("listing failed")

    monkeypatch.setattr(Path, "iterdir", exploding_iterdir)

    assert limits.prune_capped_dir(root, max_entries=1, max_bytes=1) == 0


# --------------------------------------------------------------------------- #
# _dir_size: a child that raises, and a walk that raises                      #
# --------------------------------------------------------------------------- #
def test_dir_size_skips_a_child_that_raises_mid_walk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that vanishes between listing and stat is skipped, not fatal."""

    class _RaisingChild:
        def is_file(self) -> bool:
            raise OSError("stat race")

    def fake_rglob(self: Path, pattern: str) -> Any:
        yield _RaisingChild()

    monkeypatch.setattr(Path, "rglob", fake_rglob)

    assert limits._dir_size(tmp_path) == 0


def test_dir_size_returns_what_it_has_when_the_walk_itself_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable subtree ends the walk and returns the bytes seen so far."""

    def exploding_rglob(self: Path, pattern: str) -> Any:
        raise OSError("cannot walk")

    monkeypatch.setattr(Path, "rglob", exploding_rglob)

    assert limits._dir_size(tmp_path) == 0


def test_dir_size_keeps_the_bytes_counted_before_the_walk_breaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the iterator raises partway, the running total is still returned."""
    good = tmp_path / "a.bin"
    good.write_bytes(b"x" * 10)

    def partial_rglob(self: Path, pattern: str) -> Any:
        yield good
        raise OSError("iterator died after the first child")

    monkeypatch.setattr(Path, "rglob", partial_rglob)

    assert limits._dir_size(tmp_path) == 10
