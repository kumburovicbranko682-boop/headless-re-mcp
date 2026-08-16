"""x64dbg client terminate must kill what the debugger started."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

from headless_re_mcp.backends.x64dbg.client import XdbgClient


def test_xdbg_terminate_kills_what_the_debugger_started(tmp_path: Path) -> None:
    """process.kill left the child running after the client returned.

    Measured: _terminate_process() returned in 0.001s with the parent
    gone and the sleeper it started still alive. An unattended close
    then leaked x64dbg's debuggee.
    """
    pid_path = tmp_path / "child.pid"
    launcher = tmp_path / "launcher.py"
    launcher.write_text(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.25)'])\n"
        f"open({str(pid_path)!r}, 'w').write(str(child.pid))\n"
        "while True: time.sleep(0.25)\n",
        encoding="utf-8",
    )
    process = subprocess.Popen([sys.executable, str(launcher)])
    deadline = time.monotonic() + 2.0
    while not pid_path.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    child = int(pid_path.read_text())

    class _Holder:
        _process = process

    try:
        XdbgClient._terminate_process(_Holder())
        alive = True
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.kill(child, 0)
            except OSError:
                alive = False
                break
            time.sleep(0.05)
        assert alive is False, "the process the debugger started outlived terminate"
    finally:
        with suppress(OSError):
            os.kill(child, 9)
        with suppress(OSError):
            os.kill(process.pid, 9)
