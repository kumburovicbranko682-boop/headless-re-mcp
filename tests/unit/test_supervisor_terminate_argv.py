"""Coverage for Supervisor._terminate's non-Popen arcs and child argv building.

``test_supervisor.py`` drives the loop with a FakeChild that has both terminate
and a clean wait. These pin the remaining ``_terminate`` shapes -- a child with
no terminate, a child with no wait, and a wait that times out into kill -- plus
``build_child_argv`` for serve-web.
"""

from __future__ import annotations

import subprocess

from headless_re_mcp.supervisor import Supervisor, build_child_argv


def _supervisor() -> Supervisor:
    return Supervisor(["python", "-m", "x"])


def test_terminate_kills_a_child_whose_wait_times_out() -> None:
    class _TimeoutChild:
        def __init__(self) -> None:
            self.terminated = False
            self.killed = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="x", timeout=timeout or 0.0)

        def kill(self) -> None:
            self.killed = True

    child = _TimeoutChild()
    _supervisor()._terminate(child)
    assert child.terminated is True
    assert child.killed is True


def test_terminate_tolerates_a_timed_out_child_with_no_kill() -> None:
    class _NoKillChild:
        def __init__(self) -> None:
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="x", timeout=timeout or 0.0)

    child = _NoKillChild()
    _supervisor()._terminate(child)  # wait times out but there is no kill() to call
    assert child.terminated is True


def test_terminate_skips_a_child_without_a_terminate_method() -> None:
    class _WaitOnlyChild:
        def __init__(self) -> None:
            self.waited = False

        def wait(self, timeout: float | None = None) -> int:
            self.waited = True
            return 0

    child = _WaitOnlyChild()
    _supervisor()._terminate(child)  # no terminate() to call; wait() still runs
    assert child.waited is True


def test_terminate_returns_for_a_child_without_a_wait_method() -> None:
    class _TerminateOnlyChild:
        def __init__(self) -> None:
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

    child = _TerminateOnlyChild()
    _supervisor()._terminate(child)  # terminate() runs; no wait() to await
    assert child.terminated is True


def test_build_child_argv_for_serve_web_carries_host_and_port() -> None:
    argv = build_child_argv("serve-web", host="127.0.0.1", port=8765, config="/tmp/c.json")
    assert argv[-5:] == ["serve-web", "--host", "127.0.0.1", "--port", "8765"]
    assert "--config" in argv and "/tmp/c.json" in argv


def test_build_child_argv_for_serve_web_without_host_or_port() -> None:
    argv = build_child_argv("serve-web")
    assert argv[-1] == "serve-web"
    assert "--host" not in argv
    assert "--port" not in argv
