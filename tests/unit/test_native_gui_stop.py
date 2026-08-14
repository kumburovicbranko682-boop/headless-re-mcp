"""GUI stop must wait until the owned child has actually exited."""

from __future__ import annotations

import subprocess
import sys
import time

from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.native_app.bootstrap import stop_owned_process


def test_stop_owned_process_waits_until_the_child_exits() -> None:
    """Measured: terminate() left poll() None immediately (pid still running).

    The GUI then dropped the handle, so the next start spawned a second
    serve. Overnight two MCP processes fight over IDA. Wait until the
    child is gone before forgetting it.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **no_window_popen_kwargs(),
    )
    time.sleep(0.3)
    assert proc.poll() is None
    t0 = time.perf_counter()
    stop_owned_process(proc, wait_s=5.0)
    elapsed = time.perf_counter() - t0
    assert elapsed < 8.0
    assert proc.poll() is not None
