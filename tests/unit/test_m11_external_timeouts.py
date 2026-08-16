"""External optional-backend timeout / abnormal-exit unit coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


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


def test_r2_nonzero_exit_maps_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    from headless_re_mcp.backends.common.bounded_run import Completed

    fake = Completed(returncode=2, stdout=b"", stderr=b"boom")
    with patch("headless_re_mcp.backends.r2.client.run_bounded", return_value=fake):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "backend_error"


def test_r2_timeout_kills_what_the_launcher_started(tmp_path: Path) -> None:
    """subprocess.run(timeout=) used to leave the child of a fake r2 alive.

    Measured: timeout returned and the child pid was still running.
    """
    import os
    import time
    from contextlib import suppress

    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    pidfile = tmp_path / "child.pid"
    stub = tmp_path / "r2"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        "while True:\n"
        "    time.sleep(0.2)\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    child = 0
    try:
        with pytest.raises(R2Error) as caught:
            R2Client(executable=stub).run(binary, ["i"], timeout=0.8)
        assert caught.value.code == "timeout"
        deadline = time.monotonic() + 2.0
        while not pidfile.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        child = int(pidfile.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 5.0
        while True:
            try:
                os.kill(child, 0)
                alive = True
            except OSError:
                alive = False
            if not alive or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        assert alive is False
        assert child in caught.value.details["killed_pids"]
    finally:
        if child:
            with suppress(OSError):
                os.kill(child, 9)


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
