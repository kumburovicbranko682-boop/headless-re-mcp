"""de4dot / NETReactorSlayer capture cleanup must share one drain budget.

``_capture_process`` (shared by both .NET deobfuscator adapters) joins its two
reader threads twice: once after the runner ends, and again after killing a
leftover process group. Four independent ``join(timeout=2.0)`` calls let two
readers wedged on a pipe an orphaned grandchild still holds add up to eight
seconds past the process deadline, one stream at a time -- the exact drain the
DIE / UPX / Exeinfo / x64dbg capture paths already bound. A single shared
deadline caps the whole cleanup instead.
"""

from __future__ import annotations

import io

import pytest

from headless_re_mcp.dotnet import de4dot as de4dot_mod


def test_capture_cleanup_shares_one_drain_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    join_timeouts: list[float] = []

    class _FakeProcess:
        def __init__(self) -> None:
            # pid 0 keeps the process-group side effects out of the test: the
            # ``if pid:`` assign is skipped and group_id stays 0.
            self.pid = 0
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def poll(self) -> int:
            # Already exited, so the watch loop breaks straight into cleanup.
            return 0

    class _StuckThread:
        """A reader wedged on an orphaned grandchild's pipe: never finishes."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def start(self) -> None:
            return None

        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            budget = float(timeout or 0.0)
            join_timeouts.append(budget)
            clock[0] += budget

    monkeypatch.setattr(de4dot_mod, "monotonic", lambda: clock[0])
    monkeypatch.setattr(de4dot_mod, "sleep", lambda _s: None)
    monkeypatch.setattr(de4dot_mod, "Thread", _StuckThread)
    monkeypatch.setattr(de4dot_mod, "active_bound_cancel", lambda: None)
    monkeypatch.setattr(de4dot_mod, "_terminate_process", lambda _p: None)
    monkeypatch.setattr(de4dot_mod.subprocess, "Popen", lambda *a, **k: _FakeProcess())

    capture = de4dot_mod._capture_process(["de4dot"], timeout=0.1, max_output_size=1024)

    # readers_blocked drives the leftover-children branch, so every one of the
    # four joins runs -- and their budgets must still sum to a single window.
    assert len(join_timeouts) == 4
    assert sum(join_timeouts) <= 2.0
    assert capture.returncode == 0
