from __future__ import annotations

import pytest

import headless_re_mcp.backends.ida.client as client_module
from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError


class _Process:
    pid = 6789


def test_ida_window_sightings_bound_changing_title_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changing title left one permanent string per rejected request.

    Simulating 1,000 retries retained all 1,000 titles. A caller retrying a
    progress-bearing dialog can therefore grow the session for its whole life.
    """
    client = object.__new__(IdaWorkerClient)
    client._process = _Process()  # type: ignore[assignment]
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    observation = [0]

    def changing_window(pid: int) -> list[str]:
        assert pid == 6789
        observation[0] += 1
        return [f"IDA progress {observation[0]}"]

    monkeypatch.setattr(client_module, "describe_process_windows", changing_window)

    for _ in range(1_000):
        with pytest.raises(IdaWorkerError, match="window open"):
            client._observe_windows()

    assert len(client._observed_windows) <= 128
    assert client._observed_windows_dropped >= 872
