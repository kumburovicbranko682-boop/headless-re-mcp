"""assign_to_process_group must be a harmless no-op on POSIX.

The Windows job-object path is what ties a spawned child to this process's
lifetime; on POSIX that job is not needed (the tools are started with
``start_new_session`` and reaped by ``killpg``), so ``assign_to_process_group``
is expected to do nothing and return ``False``.

What makes this worth a test is the *shape* of that no-op. Every ``run_bounded``
and ``_capture_process`` spawn calls ``assign_to_process_group(process.pid)``
unconditionally, right after Popen. The ``os.name != "nt"`` guard is the first
thing the function checks, and it short-circuits before any ctypes call. That
ordering is load-bearing: ``_kernel32()`` calls ``ctypes.WinDLL("kernel32")``,
which raises on Linux, so reordering the guard after ``_ensure_job()`` -- an
easy thing to do while refactoring -- would turn every bounded spawn on Linux
into an immediate crash. The Windows behaviour is pinned in test_supervisor;
this pins the POSIX contract the base VM actually runs.
"""

from __future__ import annotations

import os

import pytest

from headless_re_mcp import process_group

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="this pins the POSIX no-op; the Windows path is in test_supervisor"
)


@pytest.mark.parametrize("pid", [4242, 1, 0, -1])
def test_assign_is_false_on_posix_and_never_touches_kernel32(
    pid: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """False for every pid, and the Windows-only ctypes path is never reached.

    Patching ``_kernel32`` to raise turns any fall-through into a loud failure,
    so a green test proves the ``os.name`` guard really did short-circuit rather
    than the call happening to succeed.
    """

    def _boom() -> object:
        raise AssertionError("kernel32 must never be reached on POSIX")

    monkeypatch.setattr(process_group, "_kernel32", _boom)

    assert process_group.assign_to_process_group(pid) is False


def test_assign_does_not_mark_the_job_unavailable_on_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The POSIX no-op must not touch the Windows job cache or alert once.

    A POSIX call returning False through the ctypes path (rather than the guard)
    would flip the module's _unavailable latch and fire the one-time
    "process_group_unavailable" alert -- a Windows-only warning surfacing on a
    platform where the job object was never meant to exist. Pin that the shared
    state is left exactly as it was.
    """
    monkeypatch.setattr(process_group, "_job", None)
    monkeypatch.setattr(process_group, "_unavailable", False)
    monkeypatch.setattr(process_group, "_reported", False)

    alerts: list[str] = []
    monkeypatch.setattr(
        process_group, "record_alert", lambda kind, **_: alerts.append(kind)
    )

    assert process_group.assign_to_process_group(4242) is False

    # Untouched: the guard returned before any of this could change.
    assert process_group._job is None
    assert process_group._unavailable is False
    assert process_group._reported is False
    assert alerts == []
