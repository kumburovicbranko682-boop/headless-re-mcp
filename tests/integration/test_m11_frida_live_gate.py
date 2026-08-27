"""M11 Frida live gate: attach/modules/exports against a standalone process.

Frida's local attach / enumerate / hook surface is cross-platform, so this
gate runs on Linux and Windows alike: it spawns a throwaway target, attaches,
and checks the same contract -- modules, a system library's exports, the
cross-pid permission stop, and a template load. Only the target binary and the
expected system module differ by platform. skip != pass: it skips only when the
frida module is absent or the OS forbids ptrace.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _spawn_target() -> tuple[subprocess.Popen[bytes], set[str]]:
    """Start a long-lived process to attach to, and the modules to expect.

    On Windows the GUI fixture loads the Win32 core DLLs; elsewhere any process
    is dynamically linked against the C runtime, so libc is the portable
    equivalent of kernel32/ntdll.
    """
    if os.name == "nt":
        fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "gui_fixture.exe"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            [str(fixture)],
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc, {"kernel32.dll", "ntdll.dll", "user32.dll"}
    # A plain Python sleeper is guaranteed present and stays up long enough to
    # attach; like every ELF here it is dynamically linked against libc.
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, {"libc.so.6"}


@pytest.mark.integration
def test_m11_frida_devices_lists_the_local_device() -> None:
    """frida.devices is the enumeration entry point and needs no target.

    Every other frida capability starts from a device; listing them is what an
    agent calls first, yet it had no live coverage. Unlike attach, enumeration
    needs no ptrace, so this runs even on a locked-down host. Drive it through
    the service layer (frida_devices) so the real client-to-envelope path is
    exercised, and assert the always-present local device with its documented
    id/name/type shape -- a regression that returned an empty list or dropped a
    field fails here. skip != pass: skips only when frida is absent.
    """
    if not FridaClient().available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")
    service = AnalysisService()
    try:
        result = service.frida_devices()
        assert result.ok, result.error
        devices = result.data["devices"]
        assert result.data["count"] == len(devices)
        local = [d for d in devices if d.get("type") == "local"]
        assert local, f"no local frida device was enumerated: {devices}"
        entry = local[0]
        assert entry["id"] == "local"
        assert isinstance(entry["name"], str) and entry["name"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_m11_frida_live_attach_modules_exports() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")
    proc, system_modules = _spawn_target()
    try:
        time.sleep(0.5)
        assert proc.poll() is None, "target exited early"

        # A cross-pid read is refused before any attach happens.
        denied = None
        try:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        try:
            attached = client.attach(proc.pid, allowed_pid=proc.pid)
        except FridaError as exc:
            # A locked-down host (kernel.yama.ptrace_scope) refuses attach; that
            # is a missing capability, not a gate failure, so skip loudly.
            if os.name != "nt" and exc.code in {"backend_error", "timeout"}:
                pytest.skip(f"frida could not attach (ptrace restricted?): {exc.code} — skip≠pass")
            raise
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid

        mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=64)
        assert mods["count"] >= 1
        assert any(isinstance(m.get("name"), str) and m["name"] for m in mods["modules"])

        wanted = {name.lower() for name in system_modules}
        sys_module = next(
            (m for m in mods["modules"] if str(m.get("name", "")).lower() in wanted),
            None,
        )
        if sys_module is None:
            pytest.fail(f"expected one of {sorted(system_modules)} among frida modules")
        sys_mod = str(sys_module["name"])
        exports = client.exports(proc.pid, sys_mod, allowed_pid=proc.pid, limit=16)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 1
        assert isinstance(exports.get("exports"), list)

        # A module's base maps its image header, so a short read there returns
        # the real magic bytes of the target's memory -- ELF on POSIX, MZ on
        # Windows. This exercises the memory_read path against a known address.
        base = int(str(sys_module.get("base") or "0"), 0)
        if base > 0:
            read = client.memory_read(proc.pid, base, 16, allowed_pid=proc.pid)
            assert read.get("encoding") == "hex"
            data = bytes.fromhex(str(read.get("data", "")))
            assert len(data) == 16
            magic = b"MZ" if os.name == "nt" else b"\x7fELF"
            assert data.startswith(magic)

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked.get("loaded") is True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
