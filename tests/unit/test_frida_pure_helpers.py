"""Frida timeout / introspection / cleanup helpers, pinned without frida.

These pure helpers sit under every frida call, yet none had a direct test:

* ``_bound_timeout`` is the deadline guard -- it rejects a non-positive timeout
  and clamps the rest to the workflow ceiling;
* ``_accepts_timeout`` decides whether a native method may be handed a deadline,
  and must say no to a ``**kwargs``-only callable (frida ``spawn`` takes aux
  options there, so a timeout would become a spawn argument, not a hang bound);
* ``_is_timeout`` classifies an exception as a deadline by type name or message;
* ``_invoke`` passes ``timeout`` only when the method names it;
* ``_run_deadline`` bounds a native call that cannot be interrupted with a
  daemon-thread future, firing a best-effort ``on_timeout`` and raising a frida
  timeout;
* ``_detach_all`` / ``_kill_spawned`` run in ``finally`` cleanup and must drain
  their list even when a detach/kill raises.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _detach_all,
    _invoke,
    _is_timeout,
    _kill_spawned,
    _run_deadline,
    _timeout_error,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


def test_bound_timeout_returns_a_positive_value_as_float() -> None:
    assert _bound_timeout(5) == 5.0


def test_bound_timeout_clamps_to_the_workflow_ceiling() -> None:
    assert _bound_timeout(MAX_WORKFLOW_TIMEOUT * 10) == MAX_WORKFLOW_TIMEOUT


@pytest.mark.parametrize("bad", [0, -1, -0.5])
def test_bound_timeout_rejects_a_non_positive_deadline(bad: float) -> None:
    with pytest.raises(FridaError) as info:
        _bound_timeout(bad)
    assert info.value.code == "invalid_params"


def test_is_timeout_detects_by_type_name_or_message() -> None:
    assert _is_timeout(TimeoutError("x")) is True
    assert _is_timeout(RuntimeError("operation timed out")) is True
    assert _is_timeout(ValueError("unrelated")) is False


def test_accepts_timeout_requires_a_named_parameter() -> None:
    def with_timeout(target: Any, timeout: float = 1.0) -> None: ...

    def only_kwargs(**kwargs: Any) -> None: ...

    def neither(a: Any, b: Any) -> None: ...

    assert _accepts_timeout(with_timeout) is True
    # **kwargs is not a named timeout -- handing spawn a deadline there would be
    # an aux spawn option, not a hang bound.
    assert _accepts_timeout(only_kwargs) is False
    assert _accepts_timeout(neither) is False


def test_accepts_timeout_is_false_when_a_signature_cannot_be_read() -> None:
    # A non-introspectable target must read as "no timeout", not raise.
    assert _accepts_timeout(object()) is False


def test_invoke_passes_timeout_only_when_the_method_names_it() -> None:
    seen: dict[str, Any] = {}

    def accepts(x: int, timeout: float | None = None) -> str:
        seen["accepts_timeout"] = timeout
        return "a"

    def refuses(x: int, **kwargs: Any) -> str:
        seen["refuses_kwargs"] = kwargs
        return "r"

    assert _invoke(accepts, 1, timeout=7) == "a"
    assert seen["accepts_timeout"] == 7
    assert _invoke(refuses, 1, timeout=7) == "r"
    assert "timeout" not in seen["refuses_kwargs"]


def test_detach_all_drains_the_list_and_swallows_errors() -> None:
    class _Session:
        def __init__(self, boom: bool = False) -> None:
            self.boom = boom
            self.detached = False

        def detach(self) -> None:
            self.detached = True
            if self.boom:
                raise RuntimeError("session already gone")

    good = _Session()
    bad = _Session(boom=True)
    sessions = [good, bad]
    _detach_all(sessions)
    assert sessions == []
    assert good.detached is True
    assert bad.detached is True


def test_kill_spawned_drains_the_pids_and_swallows_errors() -> None:
    killed: list[int] = []

    class _Device:
        def kill(self, pid: int) -> None:
            killed.append(pid)
            if pid == 2:
                raise RuntimeError("no such process")

    pids = [1, 2, 3]
    _kill_spawned(_Device(), pids)
    assert pids == []
    assert sorted(killed) == [1, 2, 3]


def test_run_deadline_returns_the_work_result() -> None:
    assert _run_deadline(lambda: 42, timeout=5) == 42


def test_run_deadline_propagates_a_work_error() -> None:
    def boom() -> int:
        raise ValueError("work failed")

    with pytest.raises(ValueError):
        _run_deadline(boom, timeout=5)


def test_run_deadline_times_out_and_fires_on_timeout() -> None:
    fired = {"called": False}

    def slow() -> int:
        time.sleep(2)
        return 1

    def on_timeout() -> None:
        fired["called"] = True

    with pytest.raises(FridaError) as info:
        _run_deadline(slow, timeout=0.05, on_timeout=on_timeout)
    assert info.value.code == "timeout"
    assert fired["called"] is True


def test_run_deadline_times_out_without_an_on_timeout_callback() -> None:
    """With no on_timeout the deadline still fires cleanly -- the optional
    cleanup hook is skipped, not required."""

    def slow() -> int:
        time.sleep(2)
        return 1

    with pytest.raises(FridaError) as info:
        _run_deadline(slow, timeout=0.05)
    assert info.value.code == "timeout"


def test_run_deadline_suppresses_an_on_timeout_that_itself_raises() -> None:
    """A cleanup that fails must not mask the timeout the caller needs to see."""

    def slow() -> int:
        time.sleep(2)
        return 1

    def on_timeout() -> None:
        raise RuntimeError("cleanup failed")

    with pytest.raises(FridaError) as info:
        _run_deadline(slow, timeout=0.05, on_timeout=on_timeout)
    assert info.value.code == "timeout"


def test_timeout_error_is_a_frida_timeout_carrying_the_deadline() -> None:
    err = _timeout_error(3.5)
    assert err.code == "timeout"
    assert "3.5" in err.message
