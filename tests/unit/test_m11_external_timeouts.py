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
        side_effect=TimedOut(1.0, [99]),
    ):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [99]


def test_a_real_r2_timeout_returns_instead_of_waiting_out_the_child(
    tmp_path: Path,
) -> None:
    """r2 is often a script that starts radare2. Killing only it leaves the analysis.

    Measured against a launcher that starts a sleeper: a 1s deadline returned
    in 1.0s and the child was still running.
    """
    import os
    import time
    from contextlib import suppress

    marker = tmp_path / "child.pid"
    launcher = tmp_path / "r2"
    launcher.write_text(
        "#!/usr/bin/env python3\n"
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time\\nwhile True: time.sleep(0.2)'])\n"
        f"Path({str(marker)!r}).write_text(str(child.pid))\n"
        "while True: time.sleep(0.2)\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    client = R2Client(executable=launcher)
    started = time.monotonic()
    try:
        with pytest.raises(R2Error) as caught:
            client.run(binary, ["i"], timeout=0.8)
        elapsed = time.monotonic() - started
        assert caught.value.code == "timeout"
        assert elapsed < 10.0
    finally:
        if marker.is_file():
            with suppress(OSError, ValueError):
                os.kill(int(marker.read_text()), 9)


def test_r2_nonzero_exit_maps_to_backend_error(tmp_path: Path) -> None:
    from headless_re_mcp.backends.common.bounded_run import Completed

    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    fake = Completed(returncode=2, stdout=b"", stderr=b"boom")
    with patch(
        "headless_re_mcp.backends.r2.client.run_bounded",
        return_value=fake,
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
