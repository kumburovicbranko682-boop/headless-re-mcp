"""Wedged Playwright runners must not grow threads without a ceiling."""

from __future__ import annotations

import threading
from typing import Any

import pytest

import headless_re_mcp.backends.web.client as web_client
from headless_re_mcp.backends.web.client import WebError, _Runner


def test_wedged_browser_runners_refuse_threads_after_the_bound(
    monkeypatch: Any,
) -> None:
    """Closing a wedged browser cannot kill its blocked Python runner.

    Measured with a two-runner limit: two timed-out calls left two daemon
    threads blocked, and opening another session started a third. Repeating
    close/open cycles could therefore grow threads for the process lifetime.
    """
    slots = threading.BoundedSemaphore(2)
    monkeypatch.setattr(web_client, "_RUNNER_SLOTS", slots, raising=False)
    release = threading.Event()
    runners: list[_Runner] = []
    third: _Runner | None = None

    def hung() -> None:
        release.wait()

    try:
        for index in range(2):
            runner = _Runner(f"wedged-browser-{index}")
            runners.append(runner)
            with pytest.raises(WebError) as timed_out:
                runner.call(hung, timeout=0.02)
            assert timed_out.value.code == "timeout"

        with pytest.raises(WebError) as refused:
            third = _Runner("one-too-many")

        assert refused.value.code == "resource_exhausted"
    finally:
        release.set()
        for runner in runners:
            runner.shutdown()
        if third is not None:
            third.shutdown()
