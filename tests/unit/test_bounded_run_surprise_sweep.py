"""A surprise inside run_bounded must still reap the child it already spawned.

``run_bounded``'s normal exits each stop or reap the process before returning:
a clean run drains and returns, a timeout or a caller cancel kills the tree,
and a failed run that leaves an orphan holding the pipes kills that too. But the
setup that runs *after* the spawn and *before* the wait loop -- pinning the
child to the service's job/process group, starting the two reader threads -- can
itself raise. An exception there would otherwise leave the launcher (the JVM
jadx/apktool/Ghidra start, the node webcrack starts, r2 itself) running with no
code left to stop it: precisely the leaked-core-and-file-lock failure the whole
module exists to prevent, only reached by a different door.

The final ``finally`` sweep is that guard -- if the process is still alive when
``run_bounded`` unwinds for any reason, it terminates the tree. This injects the
surprise deterministically by making ``assign_to_process_group`` raise the
instant after the child is spawned, then proves the real child is gone once
``run_bounded`` unwinds, not merely signalled.
"""

from __future__ import annotations

import subprocess
import sys
from contextlib import suppress
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import run_bounded
from headless_re_mcp.core.process_tree import terminate_process_tree

_BOUNDED_RUN = "headless_re_mcp.backends.common.bounded_run"


def _boom(_pid: int) -> None:
    raise RuntimeError("assign boom")


def test_a_surprise_after_spawn_reaps_the_still_running_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A child that would outlive this test by half a minute if the sweep never
    # fired -- long enough that a survivor is unambiguous, not a race.
    cmd = [sys.executable, "-c", "import time; time.sleep(30)"]

    spawned: list[Any] = []
    real_popen = subprocess.Popen

    def _record_popen(*args: Any, **kwargs: Any) -> Any:
        proc = real_popen(*args, **kwargs)
        spawned.append(proc)
        return proc

    swept: list[Any] = []

    def _spy_terminate(proc: Any, **kwargs: Any) -> Any:
        swept.append(proc)
        return terminate_process_tree(proc, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", _record_popen)
    monkeypatch.setattr(f"{_BOUNDED_RUN}.terminate_process_tree", _spy_terminate)
    # The surprise: raised after Popen returns but before the wait loop, so the
    # only thing that can still stop the child is the finally sweep.
    monkeypatch.setattr(f"{_BOUNDED_RUN}.assign_to_process_group", _boom)

    with pytest.raises(RuntimeError, match="assign boom"):
        run_bounded(cmd, timeout=30.0)

    assert spawned, "no child was spawned; the surprise fired too early to exercise the sweep"
    proc = spawned[0]
    # The finally sweep is the only terminate on this path (the timeout, cancel
    # and failed-orphan branches never ran), so exactly this one call proves the
    # sweep executed rather than some earlier kill.
    assert swept == [proc], "the finally sweep did not terminate the spawned child"
    # And it must have actually worked: the child is dead once run_bounded
    # unwinds, not left running for its full deadline.
    assert proc.wait(timeout=5.0) is not None
    assert proc.poll() is not None, "the child survived run_bounded unwinding"
    for stream in (proc.stdout, proc.stderr):
        with suppress(Exception):
            if stream is not None:
                stream.close()
