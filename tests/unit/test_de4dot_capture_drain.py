"""The de4dot capture cleanup must bound its drain across both join phases.

The de4dot / NETReactorSlayer adapter drains its reader threads twice on the
clean-exit path: once after the runner exits, then again after it force-kills a
reparented leftover child. Each join used to wait a full two seconds per stream,
so a reader wedged on an orphaned grandchild's pipe could stretch cleanup to
roughly eight seconds beyond the caller's deadline. Both phases now share a
single two-second budget, matching the DIE / Exeinfo PE / UPX siblings.
"""

from __future__ import annotations

import io

import pytest

from headless_re_mcp.core import process_tree
from headless_re_mcp.dotnet import de4dot as de4dot_adapter


class _ExitedProcess:
    """A fake runner that has already exited cleanly (``poll()`` returns 0)."""

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self._returncode: int | None = 0
        self.killed = False
        self.pid = 4242

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9


def test_capture_cleanup_bounds_both_drain_phases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wedged reader must not let either drain phase run its full per-thread wait."""
    clock = [0.0]
    join_timeouts: list[float] = []

    def _advance_clock(seconds: float) -> None:
        clock[0] += seconds

    class _StuckThread:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def start(self) -> None:
            return None

        def is_alive(self) -> bool:
            # A reader wedged on an orphaned grandchild's pipe forces the
            # leftover-children branch, so the second drain phase runs too.
            return True

        def join(self, timeout: float | None = None) -> None:
            budget = float(timeout or 0.0)
            join_timeouts.append(budget)
            clock[0] += budget

    process = _ExitedProcess()
    monkeypatch.setattr(de4dot_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(de4dot_adapter, "Thread", _StuckThread)
    monkeypatch.setattr(de4dot_adapter, "monotonic", lambda: clock[0])
    monkeypatch.setattr(de4dot_adapter, "sleep", _advance_clock)
    monkeypatch.setattr(de4dot_adapter, "_terminate_process", lambda child: child.kill())
    monkeypatch.setattr(process_tree, "terminate_process_group", lambda group_id: None)
    monkeypatch.setattr(process_tree, "collect_process_group", lambda group_id: [])
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [])

    de4dot_adapter._capture_process(["fake-de4dot"], timeout=5.0, max_output_size=32)

    # Two drain phases with two readers each is four joins; their shared budgets
    # total no more than the two phase deadlines combined, not the eight seconds
    # that independent per-thread joins would spend.
    assert len(join_timeouts) == 4
    assert sum(join_timeouts) <= 4.0
