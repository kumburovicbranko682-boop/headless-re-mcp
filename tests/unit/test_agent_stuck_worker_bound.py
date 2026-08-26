"""Concurrent agent calls must enforce the stuck-worker ceiling atomically."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from typing import Any

import headless_re_mcp.agent.orchestrator as orchestrator_module
from headless_re_mcp.agent.orchestrator import AgentOrchestrator


def test_concurrent_agent_invocations_cannot_race_past_stuck_bound(
    monkeypatch: Any,
) -> None:
    """The caller-side count check was separate from the worker increment.

    Measured with a bound of two: two blocked handlers left the count at two,
    but a third concurrent worker still entered the backend, raising the live
    blocked-handler count to three.
    """
    monkeypatch.setattr(orchestrator_module, "_MAX_STUCK_TOOL_THREADS", 2)
    orchestrator = object.__new__(AgentOrchestrator)
    orchestrator._inflight_tools = 0
    orchestrator._inflight_lock = threading.Lock()
    release = threading.Event()
    two_started = threading.Event()
    active = 0
    active_lock = threading.Lock()
    errors: list[BaseException] = []

    def blocked(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        del name, arguments
        nonlocal active
        with active_lock:
            active += 1
            if active == 2:
                two_started.set()
        release.wait()
        return {"ok": True}

    orchestrator.catalog = SimpleNamespace(invoke=blocked)

    def invoke() -> None:
        try:
            orchestrator._invoke_counted("probe", {})
        except BaseException as exc:
            errors.append(exc)

    workers = [threading.Thread(target=invoke, daemon=True) for _ in range(2)]
    for worker in workers:
        worker.start()
    assert two_started.wait(1.0)

    third = threading.Thread(target=invoke, daemon=True)
    third.start()
    try:
        deadline = time.monotonic() + 0.2
        while third.is_alive() and time.monotonic() < deadline:
            time.sleep(0.005)

        assert active == 2
        assert len(errors) == 1
        assert "stuck" in str(errors[0])
        assert third.is_alive() is False
    finally:
        release.set()
        for worker in [*workers, third]:
            worker.join(timeout=1.0)
