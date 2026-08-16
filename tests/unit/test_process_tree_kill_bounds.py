"""A timeout kill used to miss children past the UI window cap."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

import pytest

from headless_re_mcp.core.process_tree import (
    _MAX_CHILD_PIDS,
    _MAX_KILL_DESCENDANTS,
    collect_descendants,
    enumerate_direct_children,
)


class TestKillWalkIsNotCappedByTheUiWindowLimit:
    """A launcher with more children than the UI window cap used to leak.

    Measured: 20 children, asked 64, returned 16 -- so a timeout kill
    would leave four descendants running after the caller already moved on.
    """

    @pytest.mark.skipif(
        os.name == "nt" or not hasattr(os, "fork"),
        reason="needs /proc and fork to count a live tree",
    )
    def test_a_wide_tree_is_fully_visible(self) -> None:
        script = (
            "import os, time\n"
            "for _ in range(20):\n"
            "    pid = os.fork()\n"
            "    if pid == 0:\n"
            "        time.sleep(30)\n"
            "        os._exit(0)\n"
            "print(os.getpid(), flush=True)\n"
            "time.sleep(30)\n"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            text=True,
        )
        parent = 0
        actual: list[int] = []
        try:
            assert proc.stdout is not None
            parent = int(proc.stdout.readline().strip())
            time.sleep(0.4)
            asked = enumerate_direct_children(parent, max_pids=_MAX_KILL_DESCENDANTS)
            desc = collect_descendants(parent)
            actual = _children_of(parent)
            assert len(actual) == 20
            assert len(asked) == 20
            assert len(desc) == 20
            assert _MAX_CHILD_PIDS < 20
        finally:
            for pid in [parent, *actual, *collect_descendants(parent)]:
                if pid <= 0:
                    continue
                with suppress(OSError):
                    os.kill(pid, 9)
            with suppress(Exception):
                proc.wait(timeout=2)
            with suppress(Exception):
                proc.kill()


def _children_of(parent: int) -> list[int]:
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="utf-8")
        except OSError:
            continue
        for line in status.splitlines():
            if line.startswith("PPid:"):
                if int(line.split(":", 1)[1]) == parent:
                    found.append(int(entry.name))
                break
    return found
