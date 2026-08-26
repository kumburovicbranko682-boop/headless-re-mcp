"""The _capture_process family must not wedge on a pipe a survivor still holds.

die, exeinfope, upx and de4dot each run a tool under their own capture loop and
then close the pipes from the capture thread. Closing a pipe a reader is still
blocked in ``read()`` on deadlocks on the buffered stream's lock -- the same
failure ``run_bounded`` had. A wrapper's child (or de4dot's runner child) that
inherits the pipes and outlives the tool keeps the write end open, so the reader
never sees EOF and the close hangs forever.

These tests reproduce that deterministically on POSIX by neutering the tree
kill, so a survivor keeps the pipe, and asserting the capture still returns
within its deadline. A separate test blinds the parent/child walk and checks the
session-group kill is what reaches a reparented child on the clean-exit path.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.detection import die as die_mod
from headless_re_mcp.detection import exeinfope as exeinfope_mod
from headless_re_mcp.dotnet import de4dot as de4dot_mod
from headless_re_mcp.unpack import upx as upx_mod

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="inherited-pipe orphan reproduction is POSIX"
)

# Grandchild inherits the tool's stdout/stderr (sets neither) and sleeps, so it
# keeps the capture pipes open after the tool is gone. Both pids go to argv[1]
# so the test can clean up when the tree kill is neutered.
_PIPE_HOLDER = (
    "import subprocess, sys, os, time\n"
    "child = subprocess.Popen([sys.executable, '-c',"
    " 'import time\\nwhile True: time.sleep(0.2)'])\n"
    "open(sys.argv[1], 'w').write(f'{os.getpid()} {child.pid}')\n"
    "while True: time.sleep(0.2)\n"
)

# Child is fully detached (own DEVNULL streams, close_fds) so it does not hold
# the capture pipes; the tool prints the child pid and exits 0, leaving an
# orphan the kernel reparents to init.
_EXIT0_ORPHAN = (
    "import subprocess, sys, os\n"
    "child = subprocess.Popen(\n"
    "    [sys.executable, '-c', 'import time\\nwhile True: time.sleep(0.2)'],\n"
    "    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
    "    stderr=subprocess.DEVNULL, close_fds=True,\n"
    ")\n"
    "open(sys.argv[1], 'w').write(str(child.pid))\n"
    "raise SystemExit(0)\n"
)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_pids(pidfile: Path, *, deadline_s: float = 3.0) -> list[int]:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        with suppress(OSError, ValueError):
            text = pidfile.read_text().strip()
            if text:
                return [int(tok) for tok in text.split()]
        time.sleep(0.02)
    raise AssertionError("launcher never recorded its pids")


_CAPTURE_CASES = [
    pytest.param(die_mod, die_mod.DieTimeoutError, {}, id="die"),
    pytest.param(
        exeinfope_mod,
        exeinfope_mod.ExeinfopeTimeoutError,
        {"window_observer": lambda pid: set()},
        id="exeinfope",
    ),
    pytest.param(upx_mod, upx_mod.UpxTimeoutError, {}, id="upx"),
    pytest.param(de4dot_mod, de4dot_mod.De4dotError, {}, id="de4dot"),
]


@pytest.mark.parametrize("module, timeout_exc, extra", _CAPTURE_CASES)
def test_capture_does_not_deadlock_when_a_survivor_holds_the_pipe(
    module: Any,
    timeout_exc: type[Exception],
    extra: dict[str, Any],
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """With the tree kill neutered, a survivor keeps the pipe; the close used to hang."""
    pidfile = tmp_path / "pids"
    # Neuter the tool's tree kill so nothing reaps the grandchild: the only
    # thing standing between the capture and a hang is the reader-owned close.
    monkeypatch.setattr(module, "_terminate_process", lambda process: None)

    argv = [sys.executable, "-c", _PIPE_HOLDER, str(pidfile)]
    started = time.monotonic()
    try:
        with pytest.raises(timeout_exc):
            module._capture_process(
                argv, timeout=0.8, max_output_size=4096, **extra
            )
        assert time.monotonic() - started < 12.0
    finally:
        with suppress(Exception):
            for pid in _read_pids(pidfile):
                with suppress(OSError):
                    os.kill(pid, signal.SIGKILL)


def test_de4dot_exit0_orphan_is_killed_by_the_session_group(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """On a clean exit the parent/child walk is blind to a reparented child.

    Blinding ``collect_descendants`` leaves the session-group enumeration as the
    only way to find the orphan, so it must still be dead once capture returns.
    """
    from headless_re_mcp.core import process_tree

    pidfile = tmp_path / "child.pid"
    monkeypatch.setattr(process_tree, "collect_descendants", lambda pid: [])

    argv = [sys.executable, "-c", _EXIT0_ORPHAN, str(pidfile)]
    capture = de4dot_mod._capture_process(argv, timeout=5.0, max_output_size=4096)
    assert capture.returncode == 0

    child = _read_pids(pidfile)[0]
    deadline = time.monotonic() + 5.0
    while _pid_alive(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    alive = _pid_alive(child)
    with suppress(OSError):
        os.kill(child, signal.SIGKILL)
    assert alive is False, "the reparented orphan outlived the session-group kill"
