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
