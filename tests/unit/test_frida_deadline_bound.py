"""Hung native Frida calls must not create threads without a ceiling."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

import headless_re_mcp.backends.frida.client as frida_client
from headless_re_mcp.backends.frida.client import FridaError, _run_deadline


def test_hung_frida_deadlines_refuse_work_after_the_thread_bound(
    monkeypatch: Any,
) -> None:
    """Every timed-out native call used to leave one daemon thread behind.

    Measured with a two-thread bound: two blocked calls timed out and remained
    alive, then a third call started a third thread. A long-running service
    could repeat that forever because each outer timeout freed its MCP worker.
    """
    slots = threading.BoundedSemaphore(2)
    monkeypatch.setattr(frida_client, "_DEADLINE_SLOTS", slots, raising=False)
    release = threading.Event()
    started = 0
    started_lock = threading.Lock()

    def hung() -> None:
        nonlocal started
        with started_lock:
            started += 1
        release.wait()

    try:
        for _ in range(2):
            with pytest.raises(FridaError) as timed_out:
                _run_deadline(hung, timeout=0.02)
            assert timed_out.value.code == "timeout"

        began = time.monotonic()
        with pytest.raises(FridaError) as refused:
            _run_deadline(hung, timeout=0.5)
        elapsed = time.monotonic() - began

        assert refused.value.code == "resource_exhausted"
        assert started == 2
        assert elapsed < 0.1
    finally:
        release.set()


def test_deadline_slot_is_released_when_work_completes(monkeypatch: Any) -> None:
    """A returning call must free its slot so later work is not starved."""
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(frida_client, "_DEADLINE_SLOTS", slots, raising=False)

    assert _run_deadline(lambda: 7, timeout=1.0) == 7
    assert _run_deadline(lambda: 9, timeout=1.0) == 9


def test_deadline_slot_is_released_when_work_raises(monkeypatch: Any) -> None:
    """A slot leaked on failure would refuse every later call after one error."""
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(frida_client, "_DEADLINE_SLOTS", slots, raising=False)

    def boom() -> None:
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        _run_deadline(boom, timeout=1.0)

    assert _run_deadline(lambda: 3, timeout=1.0) == 3
