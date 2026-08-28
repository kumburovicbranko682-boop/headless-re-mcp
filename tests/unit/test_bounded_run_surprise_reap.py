"""Pin run_bounded's last-resort reap when an unexpected error leaves a live child.

The deadlock and orphan suites drive every planned exit -- timeout, cancel,
clean exit, failed exit -- and each of those sets ``poll()`` before it leaves
the try block, so the ``finally`` guard that reaps a still-running child never
fires under them. What it exists for is the unplanned path: an exception
between ``Popen`` returning a live process and the first ``wait`` (here, the
process-group assignment raising) would otherwise return control to the caller
with the tool still running and no one left to stop it -- the exact process
leak run_bounded was written to prevent, now on the error path instead of the
timeout path. The guard must notice the child is alive and take it down.
"""

from __future__ import annotations

import subprocess
import sys
from contextlib import suppress
from typing import Any

import pytest

from headless_re_mcp.backends.common import bounded_run
from headless_re_mcp.core.process_tree import terminate_process_tree


def test_an_unexpected_error_before_the_first_wait_still_reaps_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A real, long-lived process so poll() is None the instant the surprise
    # lands: 30s is far longer than this test, and the guard -- not the
    # deadline -- is what must end it.
    reaped: list[subprocess.Popen[bytes]] = []

    def spy_terminate(process: Any, **kwargs: Any) -> list[int]:
        reaped.append(process)
        return terminate_process_tree(process, **kwargs)

    monkeypatch.setattr(bounded_run, "terminate_process_tree", spy_terminate)

    def boom(_pid: int) -> bool:
        # Stands in for any unexpected failure after the process is live but
        # before the loop's first wait -- the window the finally guard covers.
        raise RuntimeError("process-group assignment blew up")

    monkeypatch.setattr(bounded_run, "assign_to_process_group", boom)

    with pytest.raises(RuntimeError, match="process-group assignment blew up"):
        bounded_run.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=30.0,
        )

    assert len(reaped) == 1, "the finally guard must reap exactly the surprised run's child"
    child = reaped[0]
    # The child was alive when the guard ran (else there would be nothing to
    # reap) and dead once run_bounded returned control -- not left behind for
    # the deadline or the process's own lifetime to clean up.
    assert child.poll() is not None, "an unexpected error must not leak a running child"
    for stream in (child.stdout, child.stderr):
        if stream is not None:
            with suppress(Exception):
                stream.close()
