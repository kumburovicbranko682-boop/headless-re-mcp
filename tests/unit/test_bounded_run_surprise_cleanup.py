"""run_bounded must reap the child if setup throws before the planned exits.

Every planned return/raise in run_bounded first kills the process it spawned,
so the finally-block reap only fires on a "surprise": an exception raised
between Popen and those exits while the child is still alive. Were it not to
fire, that child -- a launcher's JVM or a sleeper the tool started -- would
outlive the failed call and keep a core and a file lock for the life of the
service. This forces the surprise by making the process-group assignment raise
right after the spawn, then proves the still-running child was terminated.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from headless_re_mcp.backends.common import bounded_run
from headless_re_mcp.core.process_tree import terminate_process_tree as real_terminate


def test_a_setup_failure_after_spawn_still_reaps_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reaped: list[int] = []

    def spy(process: Any, **kwargs: Any) -> Any:
        # Record the surprise-cleanup call, then really terminate so the sleeper
        # does not outlive the test.
        reaped.append(process.pid)
        return real_terminate(process, **kwargs)

    def boom(_pid: int) -> None:
        raise RuntimeError("process-group assignment failed")

    monkeypatch.setattr(bounded_run, "terminate_process_tree", spy)
    monkeypatch.setattr(bounded_run, "assign_to_process_group", boom)

    with pytest.raises(RuntimeError, match="process-group assignment failed"):
        bounded_run.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=30.0,
        )

    # The finally block saw a live child (poll() is None) and reaped it rather
    # than leaking it past the failed call.
    assert len(reaped) == 1
