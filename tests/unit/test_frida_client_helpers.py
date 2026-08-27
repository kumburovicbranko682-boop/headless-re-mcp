"""Device-free coverage for the Frida backend's pure primitives.

The frida unit tests all drive ``FridaClient``; the small module-level
helpers underneath -- the deadline that bounds a native call, the timeout
validator, the cleanup drains, and the paging/introspection shims -- had no
direct coverage, yet they are what keep a wedged probe from stranding a
worker or an agent resident in someone's process.

These pin, without a device or the frida module:

- ``_run_deadline`` returns the worker's value, propagates its exception,
  and on a hang raises a ``timeout`` FridaError while still running the
  cleanup callback (even if that callback itself raises).
- ``_bound_timeout`` caps at the workflow ceiling and rejects a
  non-positive deadline.
- ``_detach_all`` / ``_kill_spawned`` attempt every entry and empty the
  list even when one call raises -- a failed detach must not strand the
  sessions queued behind it.
- ``_page`` distinguishes "that is all there is" from "that is all you
  asked for" via the +1 sentinel the enumerations fetch.
- ``_accepts_timeout`` / ``_invoke`` thread a deadline only into callables
  that name ``timeout`` (never frida's ``**kwargs`` spawn options), and
  ``_is_timeout`` recognises a timeout by type name or message.
"""

from __future__ import annotations

import threading

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _detach_all,
    _invoke,
    _is_timeout,
    _kill_spawned,
    _page,
    _run_deadline,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


def test_run_deadline_returns_the_worker_result() -> None:
    assert _run_deadline(lambda: 42, timeout=5.0) == 42


def test_run_deadline_propagates_the_worker_exception() -> None:
    def work() -> int:
        raise ValueError("from the worker")

    with pytest.raises(ValueError, match="from the worker"):
        _run_deadline(work, timeout=5.0)


def test_run_deadline_times_out_and_runs_cleanup() -> None:
    release = threading.Event()
    fired: list[bool] = []

    def work() -> str:
        release.wait(5.0)
        return "late"

    try:
        with pytest.raises(FridaError) as caught:
            _run_deadline(work, timeout=0.1, on_timeout=lambda: fired.append(True))
    finally:
        release.set()
    assert caught.value.code == "timeout"
    assert fired == [True]


def test_run_deadline_times_out_without_a_cleanup_callback() -> None:
    release = threading.Event()

    def work() -> str:
        release.wait(5.0)
        return "late"

    try:
        with pytest.raises(FridaError) as caught:
            _run_deadline(work, timeout=0.1)
    finally:
        release.set()
    assert caught.value.code == "timeout"


def test_run_deadline_timeout_survives_a_failing_cleanup() -> None:
    release = threading.Event()

    def work() -> str:
        release.wait(5.0)
        return "late"

    def cleanup() -> None:
        raise RuntimeError("cleanup blew up")

    try:
        with pytest.raises(FridaError) as caught:
            _run_deadline(work, timeout=0.1, on_timeout=cleanup)
    finally:
        release.set()
    # The cleanup failure is swallowed; the caller still sees the timeout.
    assert caught.value.code == "timeout"


def test_bound_timeout_passes_through_and_caps() -> None:
    assert _bound_timeout(5.0) == 5.0
    assert _bound_timeout(MAX_WORKFLOW_TIMEOUT + 100) == MAX_WORKFLOW_TIMEOUT


@pytest.mark.parametrize("bad", [0.0, -1.0])
def test_bound_timeout_rejects_non_positive(bad: float) -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(bad)
    assert caught.value.code == "invalid_params"


class _Recorder:
    def __init__(self, calls: list[str], name: str, *, raises: bool = False) -> None:
        self._calls = calls
        self._name = name
        self._raises = raises

    def detach(self) -> None:
        self._calls.append(self._name)
        if self._raises:
            raise RuntimeError("detach failed")


def test_detach_all_drains_every_session_despite_a_failure() -> None:
    calls: list[str] = []
    # LIFO order: the list is popped from the end.
    sessions = [
        _Recorder(calls, "s1"),
        _Recorder(calls, "s2", raises=True),
        _Recorder(calls, "s3"),
    ]
    _detach_all(sessions)
    assert sessions == []
    assert sorted(calls) == ["s1", "s2", "s3"]


class _Device:
    def __init__(self, killed: list[int], *, fail_pid: int | None = None) -> None:
        self._killed = killed
        self._fail_pid = fail_pid

    def kill(self, pid: int) -> None:
        self._killed.append(pid)
        if pid == self._fail_pid:
            raise RuntimeError("kill failed")


def test_kill_spawned_drains_every_pid_despite_a_failure() -> None:
    killed: list[int] = []
    pids = [101, 202, 303]
    _kill_spawned(_Device(killed, fail_pid=202), pids)
    assert pids == []
    assert sorted(killed) == [101, 202, 303]


def test_page_distinguishes_full_from_capped() -> None:
    assert _page([1, 2, 3], 5) == ([1, 2, 3], False)
    # Exactly the page size is complete, not "maybe more".
    assert _page([1, 2, 3], 3) == ([1, 2, 3], False)
    # One past the page is the +1 sentinel: trimmed, and has_more is True.
    assert _page([1, 2, 3, 4], 3) == ([1, 2, 3], True)
    assert _page(None, 3) == ([], False)


def test_is_timeout_recognises_name_and_message() -> None:
    assert _is_timeout(TimeoutError()) is True
    assert _is_timeout(Exception("the operation timed out")) is True
    assert _is_timeout(ValueError("nope")) is False


def test_accepts_timeout_only_when_named() -> None:
    def has_timeout(a: int, timeout: float = 1.0) -> None:
        del a, timeout

    def kwargs_only(a: int, **kwargs: object) -> None:
        del a, kwargs

    def plain(a: int) -> None:
        del a

    assert _accepts_timeout(has_timeout) is True
    # **kwargs must NOT count: on frida.spawn that would be a spawn arg.
    assert _accepts_timeout(kwargs_only) is False
    assert _accepts_timeout(plain) is False
    # Something signature() cannot introspect degrades to False, not a crash.
    assert _accepts_timeout(object()) is False


def test_invoke_threads_timeout_only_into_accepting_callables() -> None:
    def with_timeout(a: int, timeout: float | None = None) -> tuple[int, float | None]:
        return a, timeout

    def without(a: int) -> int:
        return a

    assert _invoke(with_timeout, 7, timeout=3.0) == (7, 3.0)
    assert _invoke(without, 7, timeout=3.0) == 7
