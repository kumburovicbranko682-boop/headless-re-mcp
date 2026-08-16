"""External optional-backend timeout / abnormal-exit unit coverage."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    import ctypes

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _r2_launcher(tmp_path: Path) -> tuple[Path, Path]:
    """A stub r2 that starts a child and then hangs, like a .bat launching r2."""
    body = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        "Path(__file__).with_suffix('.child').write_text(str(child.pid))\n"
        "while True:\n"
        "    time.sleep(0.2)\n"
    )
    script = tmp_path / "r2_launcher.py"
    script.write_text(body, encoding="utf-8")
    marker = script.with_suffix(".child")
    if os.name == "nt":
        wrapper = tmp_path / "r2.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        return wrapper, marker
    script.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    script.chmod(0o755)
    return script, marker


def test_r2_timeout_maps_to_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with patch(
        "headless_re_mcp.backends.r2.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_r2_timeout_kills_what_the_launcher_started(tmp_path: Path) -> None:
    """r2 is often a script that starts the real binary.

    ``subprocess.run(timeout=...)`` kills only that script. Measured: a 0.5s
    timeout returned while the child it started was still alive, holding the
    sample for the rest of the service's life.
    """
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub, marker = _r2_launcher(tmp_path)
    client = R2Client(executable=stub)

    child = 0
    try:
        with pytest.raises(R2Error) as caught:
            client.run(binary, ["i"], timeout=0.5)
        assert caught.value.code == "timeout"

        deadline = time.monotonic() + 3.0
        while not marker.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.is_file(), "the launcher never reported the child it started"
        child = int(marker.read_text().strip())
        while _alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _alive(child) is False, "the launcher's child outlived the r2 timeout"
        assert child in caught.value.details.get("killed_pids", [])
    finally:
        if child and _alive(child):
            os.kill(child, 9)


def test_r2_nonzero_exit_maps_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    from headless_re_mcp.backends.common.bounded_run import Completed

    fake = Completed(returncode=2, stdout=b"", stderr=b"boom")
    with patch(
        "headless_re_mcp.backends.r2.client.run_bounded", return_value=fake
    ), pytest.raises(R2Error) as exc:
        client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "backend_error"


def test_windbg_dump_timeout_maps_to_timeout(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    # The bounded runner is the seam now: it kills the tree before it raises, so
    # the timeout a caller sees is the one it reports here.
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(WindbgError) as exc:
            client.open_dump(dump, ["lm"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_windbg_live_timeout_maps_to_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(WindbgError) as exc:
            client.attach(1234, allowed_pid=1234, timeout=1.0)
    assert exc.value.code == "timeout"
