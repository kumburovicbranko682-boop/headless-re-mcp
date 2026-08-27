"""Portable Frida live gate: attach to a local child and read its memory.

The Windows fixture gate (test_m11_frida_live_gate.py) is force-skipped on Linux
by conftest and never exercised ``frida.read`` at all, so frida 17's removal of
``Memory.readByteArray`` -- which broke every read on a current install -- had no
live coverage on any platform. This spawns a child of the test process, so the
attach is permitted even under a restrictive ``ptrace_scope``, and drives
modules/exports/read plus the pid authorization gate. It runs wherever frida is
installed rather than only on a Windows build.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _spawn_child() -> subprocess.Popen[bytes]:
    # A Python child is dynamically linked with named exports on every platform,
    # and being our own child keeps the attach allowed where ptrace_scope is 1.
    return subprocess.Popen(
        [sys.executable, "-c", "import time\nwhile True: time.sleep(0.2)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.mark.integration
def test_frida_local_attach_modules_exports_read() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")
    proc = _spawn_child()
    try:
        time.sleep(0.5)
        assert proc.poll() is None, "child exited early"
        pid = proc.pid

        # Authorization gate: a pid outside the allow-set is refused before any
        # attach happens, so the read/enumerate paths below cannot be reached
        # with an unapproved target.
        with pytest.raises(FridaError) as denied:
            client.modules(pid, allowed_pid=pid + 1, limit=4)
        assert denied.value.code == "permission_denied"

        attached = client.attach(pid, allowed_pid=pid)
        assert attached["attached"] is True
        assert attached["pid"] == pid

        mods = client.modules(pid, allowed_pid=pid, limit=128)
        assert mods["count"] >= 1
        assert all(isinstance(m.get("name"), str) and m["name"] for m in mods["modules"])

        # Find a module that actually exports symbols; the main executable often
        # has none, so probe the first loaded library that does.
        exported: tuple[dict[str, object], dict[str, object]] | None = None
        for module in mods["modules"][:24]:
            found = client.exports(pid, str(module["name"]), allowed_pid=pid, limit=8)
            if found.get("found") and int(found.get("count", 0) or 0) >= 1:
                exported = (module, found)
                break
        assert exported is not None, "no loaded module reported exports"
        module, exports = exported
        assert isinstance(exports["exports"], list) and exports["exports"]

        # frida.read must return real bytes: a module's base carries the
        # platform's executable magic. This is the exact path frida 17 broke by
        # dropping Memory.readByteArray, and a broken read raises rather than
        # returning short, so any return proves the modern API is in use.
        base = int(str(module["base"]), 16)
        mem = client.memory_read(pid, base, 4, allowed_pid=pid)
        data = bytes.fromhex(str(mem["data"]))
        assert len(data) == 4
        if sys.platform == "linux":
            assert data == b"\x7fELF"
        elif sys.platform == "win32":
            assert data[:2] == b"MZ"

        # A canned hook loads and is honestly reported as not surviving detach.
        hooked = client.hook_template(pid, "noop", allowed_pid=pid)
        assert hooked["loaded"] is True
        assert hooked["persisted"] is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
