"""Frida live gate on the POSIX core: attach/modules/exports/memory_read/hook.

The only other frida live gate (``test_m11_frida_live_attach_modules_exports``)
needs a Windows PE fixture that does not ship with the Linux core, so on this
platform frida -- installed and fully functional -- had zero live coverage, and
that gate never read memory at all. That blind spot let a real regression ship:
frida 17 removed the ``Memory.read*`` helpers, so ``memory_read``'s injected
script called a function that no longer exists and failed on every modern frida
while ``modules``/``exports`` (which use ``Process.*``) kept working.

This attaches to a throwaway local process, drives the whole read surface, and
asserts ``memory_read`` returns the ELF magic at a module base -- the assertion
that would have caught the removed-API bug. skip != pass: no frida, no target,
or a ptrace-restricted host each skip rather than quietly succeed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _spawn_local_target() -> subprocess.Popen[bytes]:
    exe = shutil.which("sleep")
    if exe is None:
        pytest.skip("no 'sleep' binary for a local frida target — skip != pass")
    proc = subprocess.Popen([exe, "300"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    if proc.poll() is not None:
        pytest.skip("local target exited early — skip != pass")
    return proc


@pytest.mark.integration
def test_frida_local_read_surface_including_memory_read() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live gate not run (skip != pass)")
    if sys.platform == "win32":
        pytest.skip("POSIX-core gate; the M11 gate covers Windows PE (skip != pass)")

    proc = _spawn_local_target()
    try:
        # The per-session pid boundary must hold on the live path, not just in
        # the mocked unit test: a pid the session was not handed is refused.
        with pytest.raises(FridaError) as denied:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        assert denied.value.code == "permission_denied"

        attached = client.attach(proc.pid, allowed_pid=proc.pid)
        assert attached["attached"] is True
        assert attached["pid"] == proc.pid

        try:
            mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=64)
        except FridaError as exc:
            # A host with yama ptrace_scope locked down cannot attach locally;
            # that is an environment property, not a defect. Skip honestly.
            if exc.code in {"backend_error", "timeout"}:
                pytest.skip(
                    f"cannot attach to a local process (ptrace restricted?): "
                    f"{exc.message} — skip != pass"
                )
            raise
        assert mods["count"] >= 1
        by_name = {str(m["name"]): m for m in mods["modules"]}
        libc = next((name for name in by_name if "libc" in name), None)
        assert libc is not None, f"libc not among frida modules: {sorted(by_name)}"

        exports = client.exports(proc.pid, libc, allowed_pid=proc.pid, limit=16)
        assert exports["found"] is True
        assert exports["count"] >= 1
        assert isinstance(exports["exports"], list)

        # The regression guard: read the ELF header at libc's mapped base. With
        # the removed Memory.readByteArray this raised "TypeError: not a
        # function"; with the NativePointer read it returns the ELF magic.
        base = int(str(by_name[libc]["base"]), 16)
        read = client.memory_read(proc.pid, base, 4, allowed_pid=proc.pid)
        assert read["encoding"] == "hex"
        assert read["size"] == 4
        assert read["data"] == "7f454c46", f"expected ELF magic at libc base, got {read['data']}"

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked["loaded"] is True
        assert hooked["persisted"] is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
