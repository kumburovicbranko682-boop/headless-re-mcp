"""Coverage for the limits helpers' Windows memory probe and OSError arms.

The shared eviction suite covers the POSIX and happy paths; these reach the
Windows ``GlobalMemoryStatusEx`` branch (with a faked ``windll``) and the
``OSError`` fall-throughs in ``prune_capped_dir`` and ``_dir_size``.
"""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core import limits


def _fake_windll(return_value: int) -> SimpleNamespace:
    return SimpleNamespace(
        kernel32=SimpleNamespace(GlobalMemoryStatusEx=lambda _ptr: return_value)
    )


def test_available_memory_reads_the_windows_status_struct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "windll", _fake_windll(1), raising=False)
    # The faked call succeeds but leaves ullAvailPhys at its zero default.
    assert limits.available_memory_bytes() == 0


def test_available_memory_returns_none_when_the_windows_call_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "windll", _fake_windll(0), raising=False)
    assert limits.available_memory_bytes() is None


def test_prune_returns_zero_when_the_directory_cannot_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "captures"
    root.mkdir()

    def _raise(self: Path) -> object:
        raise OSError("cannot list")

    monkeypatch.setattr(Path, "iterdir", _raise)
    assert limits.prune_capped_dir(root, max_entries=1, max_bytes=1) == 0


def test_dir_size_skips_a_child_it_cannot_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.bin").write_bytes(b"x" * 10)

    real_stat = Path.stat

    def _raise(self: Path) -> object:
        if self.name == "a.bin":
            raise OSError("stat refused")
        return real_stat(self)

    monkeypatch.setattr(Path, "is_file", lambda self: True)
    monkeypatch.setattr(Path, "stat", _raise)
    assert limits._dir_size(root) == 0


def test_dir_size_returns_partial_total_when_the_walk_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    root.mkdir()

    def _raise(self: Path, _pattern: str) -> object:
        raise OSError("walk refused")

    monkeypatch.setattr(Path, "rglob", _raise)
    assert limits._dir_size(root) == 0
