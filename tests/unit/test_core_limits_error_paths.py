"""Error-path coverage for the shared bounding helpers in core/limits.

``test_core_limits_eviction.py`` pins the eviction arithmetic and the POSIX
memory probe. This file drives the remaining fail-soft edges: the Windows
``GlobalMemoryStatusEx`` arm of the memory probe (exercised here on any host by
faking ``ctypes.windll``), and the directory helpers swallowing an OSError while
listing or walking a capture tree so a transient filesystem error degrades to
"evicted nothing" / "counted what I could" instead of crashing the caller that
just wrote a file.
"""

from __future__ import annotations

import ctypes
import sys
import types
from pathlib import Path

import pytest

from headless_re_mcp.core import limits


# --------------------------------------------------------------------------- #
# available_memory_bytes: the Windows probe arm                               #
# --------------------------------------------------------------------------- #
def test_available_memory_reads_the_windows_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Win32 arm calls GlobalMemoryStatusEx and returns ullAvailPhys.

    Forcing ``sys.platform`` and supplying a fake ``ctypes.windll`` lets this
    run on the POSIX CI host. The fake reports success without mutating the
    struct, so the zero-initialised ullAvailPhys is what comes back -- proving
    the field is read, not that a particular number is produced.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    seen: list[object] = []

    def probe(pointer: object) -> int:
        seen.append(pointer)
        return 1

    fake = types.SimpleNamespace(kernel32=types.SimpleNamespace(GlobalMemoryStatusEx=probe))
    monkeypatch.setattr(ctypes, "windll", fake, raising=False)

    assert limits.available_memory_bytes() == 0
    assert seen, "the Windows memory probe must actually be invoked"


def test_available_memory_returns_none_when_the_windows_probe_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero return from GlobalMemoryStatusEx means "don't guess" -> None."""
    monkeypatch.setattr(sys, "platform", "win32")
    fake = types.SimpleNamespace(
        kernel32=types.SimpleNamespace(GlobalMemoryStatusEx=lambda _pointer: 0)
    )
    monkeypatch.setattr(ctypes, "windll", fake, raising=False)

    assert limits.available_memory_bytes() is None


# --------------------------------------------------------------------------- #
# prune_capped_dir: listing failure                                           #
# --------------------------------------------------------------------------- #
def test_prune_reports_nothing_when_the_directory_cannot_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory that exists but refuses to enumerate must not raise.

    ``is_dir`` succeeds, then ``iterdir`` fails (a permission or IO error on the
    capture root). The prune reports nothing removed rather than letting the
    OSError escape into the caller that just wrote a capture.
    """
    root = tmp_path / "captures"
    root.mkdir()

    def deny_listing(_self: Path) -> object:
        raise OSError("listing denied")

    monkeypatch.setattr(Path, "iterdir", deny_listing)
    assert limits.prune_capped_dir(root, max_entries=1, max_bytes=1) == 0


# --------------------------------------------------------------------------- #
# _dir_size: walk failures                                                    #
# --------------------------------------------------------------------------- #
def test_dir_size_returns_the_partial_total_when_the_walk_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the recursive walk itself raises, the bytes counted so far stand."""
    sub = tmp_path / "tree"
    sub.mkdir()

    def deny_walk(_self: Path, _pattern: str) -> object:
        raise OSError("walk failed")

    monkeypatch.setattr(Path, "rglob", deny_walk)
    assert limits._dir_size(sub) == 0


def test_dir_size_skips_a_child_it_cannot_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single child whose is_file/stat raises is skipped, not fatal.

    The walk yields one entry that errors when probed (a vanished or unreadable
    path mid-walk); ``_dir_size`` swallows it and moves on, returning the sum of
    what it could measure.
    """

    class _Flaky:
        def is_file(self) -> bool:
            raise OSError("stat denied")

    def one_flaky_child(_self: Path, _pattern: str) -> object:
        return iter([_Flaky()])

    monkeypatch.setattr(Path, "rglob", one_flaky_child)
    sub = tmp_path / "tree"
    sub.mkdir()
    assert limits._dir_size(sub) == 0
