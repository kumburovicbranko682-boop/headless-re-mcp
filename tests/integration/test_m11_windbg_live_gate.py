"""M11 WinDbg user-mode live gate (cdb -pv). skip≠pass when cdb missing."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError
from headless_re_mcp.config import Settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_m11_windbg_live_usermode_probe() -> None:
    # Prefer the configured cdb; discovery alone can only find a Store package
    # path that Windows refuses to launch.
    client = WindbgClient(Settings.load().cdb)
    if not client.available:
        pytest.skip("cdb/WinDbg not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "gui_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    proc = subprocess.Popen(
        [str(fixture)],
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.5)
        assert proc.poll() is None, "fixture exited early"

        with pytest.raises(WindbgError) as denied:
            client.attach(proc.pid, allowed_pid=proc.pid + 1)
        assert denied.value.code == "permission_denied"

        attached = client.attach(proc.pid, allowed_pid=proc.pid, timeout=30.0)
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid
        assert attached.get("mode") == "noninvasive"

        threads = client.live_threads(proc.pid, allowed_pid=proc.pid, timeout=30.0)
        assert isinstance(threads.get("threads"), str)

        modules = client.live_modules(proc.pid, allowed_pid=proc.pid, timeout=30.0)
        assert isinstance(modules.get("modules"), str)
        assert modules.get("modules")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
