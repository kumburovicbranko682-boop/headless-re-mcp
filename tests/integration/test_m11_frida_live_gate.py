"""M11 Frida live gate: attach/modules/exports against a standalone process.

The PE test needs a Windows fixture and probes ``kernel32.dll``, so it only
runs on Windows. Frida itself is cross-platform, and so is ``FridaClient`` --
its script uses ``Process.enumerateModules`` / ``enumerateExports``, which
enumerate ELF images just as well as PE ones. The Linux-native test below
attaches to a process we spawn ourselves and probes ``libc`` instead, so the
frida backend is actually exercised on Linux rather than always skipping for a
missing ``.exe``. Both skip honestly, and skip != pass.
"""

from __future__ import annotations

import os
import subprocess
import sys
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


@pytest.mark.integration
def test_m11_frida_live_linux_modules_exports_and_memory() -> None:
    if os.name != "posix":
        pytest.skip("Linux-native frida gate: POSIX only (the PE fixture test covers Windows)")
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")

    # A long-lived child we own. Attaching to a descendant is permitted even
    # under yama ptrace_scope=1, and spawning python keeps the target
    # independent of whichever coreutils/libc happen to be installed.
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.6)
        assert proc.poll() is None, "sleeper exited early"

        # The per-session pid allow-list is enforced identically on every OS.
        denied = None
        try:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        attached = client.attach(proc.pid, allowed_pid=proc.pid)
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid

        mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=64)
        assert mods["count"] >= 1
        assert any(isinstance(m.get("name"), str) and m["name"] for m in mods["modules"])

        # libc is loaded by every dynamically linked ELF and always carries
        # exports, so it is the portable analogue of the PE test's kernel32 probe.
        libc = next(
            (m for m in mods["modules"] if "libc" in str(m.get("name", "")).lower()),
            None,
        )
        if libc is None:
            pytest.skip("no libc module in the target (static build?) — skip != pass")
        libc_name = str(libc["name"])

        exports = client.exports(proc.pid, libc_name, allowed_pid=proc.pid, limit=16)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 1
        assert any(str(item.get("name")) for item in exports["exports"])
        assert all(str(item.get("address", "")).startswith("0x") for item in exports["exports"])

        # The module base is the start of libc's first mapped segment, i.e. its
        # ELF header. Reading four bytes there proves memory_read returns real
        # mapped bytes (the exact hex length asked for), and the ELF magic makes
        # it a content check rather than "did not throw". The PE gate never
        # exercised memory_read at all.
        base = str(libc.get("base") or "")
        assert base.startswith("0x"), mods
        read = client.memory_read(proc.pid, int(base, 16), 4, allowed_pid=proc.pid)
        assert read.get("encoding") == "hex"
        assert read.get("data") == "7f454c46", read

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked.get("loaded") is True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
