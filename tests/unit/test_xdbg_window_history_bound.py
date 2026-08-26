from __future__ import annotations

from threading import Lock

from headless_re_mcp.backends.x64dbg.client import XdbgClient


class _StopAfter:
    def __init__(self, observations: int) -> None:
        self.observations = observations
        self.calls = 0

    def wait(self, timeout: float) -> bool:
        del timeout
        self.calls += 1
        return self.calls > self.observations


def test_xdbg_window_monitor_bounds_changing_title_history() -> None:
    """A changing analyzer title added one permanent string every 50 ms.

    Simulating 1,000 monitor ticks retained all 1,000 titles. At production's
    20 Hz, an animated title can otherwise add 1.7 million strings per day.
    """
    client = object.__new__(XdbgClient)
    stop = _StopAfter(1_000)
    client._monitor_stop = stop  # type: ignore[assignment]
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    client._desktop = None
    client._describe_analyzer_windows = lambda: [f"progress {stop.calls}"]  # type: ignore[method-assign]

    client._monitor_windows()

    assert len(client._observed_windows) <= 128
    assert client._observed_windows_dropped >= 872
