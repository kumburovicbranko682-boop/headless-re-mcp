"""IDA worker teardown must honor one caller-visible deadline."""

from __future__ import annotations

from threading import RLock
from typing import Any

import pytest

import headless_re_mcp.backends.ida.client as client_module
from headless_re_mcp.backends.ida.client import IdaWorkerClient


def test_close_uses_one_deadline_across_request_and_process_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The close RPC and process wait must not each consume the full timeout."""
    clock = [0.0]
    request_timeouts: list[float] = []
    wait_timeouts: list[float] = []

    class _Stdin:
        def close(self) -> None:
            return None

    class _Process:
        stdin = _Stdin()

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            budget = float(timeout or 0.0)
            wait_timeouts.append(budget)
            clock[0] += budget
            return 0

    client = object.__new__(IdaWorkerClient)
    client._request_lock = RLock()
    client._closed = False
    client._process = _Process()  # type: ignore[assignment]

    def request(
        command: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        del command, params
        request_timeouts.append(timeout)
        clock[0] += timeout
        return {}

    client.request = request  # type: ignore[method-assign]
    monkeypatch.setattr(client_module.time, "monotonic", lambda: clock[0])

    client.close(timeout=10.0)

    delegated = sum(request_timeouts) + sum(wait_timeouts)
    assert delegated <= 10.0
    assert clock[0] <= 10.0
