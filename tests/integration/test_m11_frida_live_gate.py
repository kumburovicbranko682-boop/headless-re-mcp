"""M11 Frida live gate: attach/modules/exports against a standalone process."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_m11_frida_live_attach_modules_exports() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")
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

        denied = None
        try:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        attached = client.attach(proc.pid, allowed_pid=proc.pid)
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid

        mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=8)
        assert mods["count"] >= 1
        assert any(isinstance(m.get("name"), str) and m["name"] for m in mods["modules"])

        # Main fixture PE may have zero exports; probe a loaded system DLL.
        sys_mod = next(
            (
                str(m["name"])
                for m in mods["modules"]
                if str(m.get("name", "")).lower() in {"kernel32.dll", "ntdll.dll", "user32.dll"}
            ),
            None,
        )
        if sys_mod is None:
            pytest.fail("expected kernel32/ntdll/user32 among frida modules")
        exports = client.exports(proc.pid, sys_mod, allowed_pid=proc.pid, limit=16)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 1
        assert isinstance(exports.get("exports"), list)

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked.get("loaded") is True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
