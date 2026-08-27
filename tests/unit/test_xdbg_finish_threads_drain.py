"""x64dbg teardown must bound its reader-thread drain to one shared budget.

``_finish_threads`` joined the window, stdout, and stderr threads for two
seconds each, so a grandchild that inherited (and still held open) a capture
pipe could stretch a session close/terminate to roughly six seconds. The three
joins now share a single two-second drain deadline, matching the bounded
subprocess capture adapters.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.x64dbg import client as xdbg_client
from headless_re_mcp.backends.x64dbg.client import XdbgClient


def test_finish_threads_shares_one_drain_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    join_timeouts: list[float] = []

    class _StuckThread:
        """A reader wedged on a survivor's pipe: every join burns its full wait."""

        def join(self, timeout: float | None = None) -> None:
            budget = float(timeout or 0.0)
            join_timeouts.append(budget)
            clock[0] += budget

    class _Stop:
        def set(self) -> None:
            return None

    monkeypatch.setattr(xdbg_client.time, "monotonic", lambda: clock[0])

    client = XdbgClient.__new__(XdbgClient)
    client._monitor_stop = _Stop()
    client._window_thread = _StuckThread()
    client._stdout_thread = _StuckThread()
    client._stderr_thread = _StuckThread()

    client._finish_threads()

    assert len(join_timeouts) == 3
    assert sum(join_timeouts) <= 2.0
