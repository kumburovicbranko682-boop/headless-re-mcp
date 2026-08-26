"""Every _capture_process adapter must surface a caller cancel identically.

die, exeinfope, upx and de4dot converged onto one capture paradigm, so a caller
cancel (an ``active_bound_cancel`` event set mid-run) has to stop the tool and
surface as ``BoundedCancelled`` in all four -- not only the de4dot variant the
resource-bounds suite already pins. A regression in any one adapter's cancel
check would otherwise let that tool run to its full deadline while its siblings
returned at once, the exact inconsistency the convergence removed.

Cross-platform on purpose: the cancel check is the same code on POSIX and
Windows, so this runs (and gates) on both, unlike the POSIX-only orphan-kill
reproductions.
"""

from __future__ import annotations

import sys
import time
from threading import Event, Thread
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    bound_cancel_scope,
)
from headless_re_mcp.detection import die as die_mod
from headless_re_mcp.detection import exeinfope as exeinfope_mod
from headless_re_mcp.dotnet import de4dot as de4dot_mod
from headless_re_mcp.unpack import upx as upx_mod

# A child that never exits on its own, so only the cancel (not the tool
# finishing) can end the capture.
_SLEEP_FOREVER = "import time\nwhile True: time.sleep(0.2)\n"

_CAPTURE_CASES = [
    pytest.param(die_mod, {}, id="die"),
    # exeinfope also polls for analyzer windows; a no-window observer keeps the
    # test off any real GUI probe so only the cancel path is exercised.
    pytest.param(exeinfope_mod, {"window_observer": lambda pid: set()}, id="exeinfope"),
    pytest.param(upx_mod, {}, id="upx"),
    pytest.param(de4dot_mod, {}, id="de4dot"),
]


@pytest.mark.parametrize("module, extra", _CAPTURE_CASES)
def test_capture_process_surfaces_a_bound_cancel(
    module: Any, extra: dict[str, Any]
) -> None:
    cancel = Event()

    def fire() -> None:
        time.sleep(0.2)
        cancel.set()

    Thread(target=fire, daemon=True).start()
    started = time.monotonic()
    with pytest.raises(BoundedCancelled), bound_cancel_scope(cancel):
        module._capture_process(
            [sys.executable, "-c", _SLEEP_FOREVER],
            timeout=20.0,
            max_output_size=4096,
            **extra,
        )
    # The cancel fires at ~0.2s against a 20s deadline: if the deadline is what
    # ended the wait this assertion fails, catching an adapter that stopped
    # checking the cancel event.
    assert time.monotonic() - started < 8.0
