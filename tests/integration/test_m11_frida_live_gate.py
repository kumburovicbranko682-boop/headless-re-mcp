"""M11 Frida live gate: attach/modules/exports/memory.read against a process.

Portable across the platforms this backend runs on. Windows keeps its PE
fixture and probes the system DLLs it always loads; elsewhere any process loads
the C runtime, so a sleeping Python interpreter is target enough and needs no
fixture. The frida client operations (attach, modules, exports, memory_read,
hook_template) are themselves platform-agnostic -- only the target and the name
of a system library with exports differ -- so the same assertions run on both.
It skips, never fails, when frida is absent or the OS forbids a local attach
(ptrace restrictions on Linux, an unsigned interpreter on macOS): skip != pass.
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


def _spawn_target() -> tuple[subprocess.Popen[bytes], tuple[str, ...]]:
    """A live local process to attach to, plus name fragments of a system
    library among its modules that is guaranteed to export symbols.

    Returns ``(process, markers)`` where ``markers`` are lowercase substrings
    that identify the module worth probing for exports on this platform.
    """
    if os.name == "nt":
        fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "gui_fixture.exe"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        proc = subprocess.Popen(
            [str(fixture)],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc, ("kernel32.dll", "ntdll.dll", "user32.dll")
    # A sleeping interpreter loads libc/ld and stays put for the whole gate.
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, ("libc.so", "libc-", "libsystem_c")


@pytest.mark.integration
def test_m11_frida_live_attach_modules_exports() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")

    proc, sys_markers = _spawn_target()
    try:
        time.sleep(0.5)
        assert proc.poll() is None, "fixture exited early"

        # The single-pid guard must refuse a pid the session did not authorise.
        denied = None
        try:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        try:
            attached = client.attach(proc.pid, allowed_pid=proc.pid)
        except FridaError as exc:
            if os.name != "nt":
                pytest.skip(
                    f"frida could not attach locally ({exc.code}: {exc}) — "
                    f"often ptrace_scope/codesign; skip != pass"
                )
            raise
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid

        mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=64)
        assert mods["count"] >= 1
        assert any(isinstance(m.get("name"), str) and m["name"] for m in mods["modules"])

        sys_module = next(
            (
                m
                for m in mods["modules"]
                if any(marker in str(m.get("name", "")).lower() for marker in sys_markers)
            ),
            None,
        )
        if sys_module is None:
            pytest.fail(f"expected a system library ({sys_markers}) among frida modules")
        sys_mod = str(sys_module["name"])
        exports = client.exports(proc.pid, sys_mod, allowed_pid=proc.pid, limit=16)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 1
        assert isinstance(exports.get("exports"), list)

        # memory.read shares the local-read path (attach + enum script) with
        # modules/exports and is the one reader the gate did not exercise live.
        # Read the image header at the module base and confirm the real bytes
        # are the platform's executable magic: ELF (7f 45 4c 46) on POSIX, MZ
        # (4d 5a) on a Windows PE. A wrong address or a broken read cannot fake
        # this, so it pins the read to a known-correct value.
        base = str(sys_module.get("base", ""))
        assert base.startswith("0x"), f"module base is not a hex address: {base!r}"
        read = client.memory_read(proc.pid, int(base, 16), 4, allowed_pid=proc.pid)
        assert read.get("size") == 4
        assert read.get("encoding") == "hex"
        magic = str(read.get("data", "")).lower()
        if os.name == "nt":
            assert magic.startswith("4d5a"), f"expected an MZ header at the base, got {magic!r}"
        else:
            assert magic == "7f454c46", f"expected the ELF magic at the base, got {magic!r}"

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked.get("loaded") is True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
