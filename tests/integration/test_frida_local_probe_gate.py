"""frida live gate: attach + enumerate + memory read against a local process.

frida is the most version-sensitive backend here: frida 17 removed the legacy
``Memory.read*`` globals, which broke ``frida.memory.read``'s injected script at
runtime while every fake-based unit test kept passing. The companion unit test
(``test_frida_memory_read_api``) pins the script *text* statically, but only a
real attach proves the whole ``_ENUM_SCRIPT`` -- modules / exports / read --
actually runs on the installed frida.

This gate spawns a benign local process, drives ``FridaClient`` end to end, and
asserts the read path returns the loaded image's magic bytes (the exact call
that regressed). It skips (skip != pass) when frida is not installed or the
sandbox forbids attaching (no ptrace, no frida-server) -- never on an assertion.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


@pytest.mark.integration
def test_frida_local_attach_enumerate_and_read() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida module not installed — frida live Gate not run (skip != pass)")

    # A quiet, self-terminating child we fully control; killed in finally.
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.5)
    pid = proc.pid
    try:
        try:
            attached = client.attach(pid, allowed_pid=pid)
        except FridaError as exc:
            # The sandbox may forbid ptrace / lack a usable frida-server; that is
            # an environment limit, not a product failure, so skip rather than fail.
            pytest.skip(f"frida cannot attach here ({exc.code}: {exc.message}) — skip != pass")
        assert attached["attached"] is True

        # modules: enumerateModules must return the process image tree.
        mods = client.modules(pid, allowed_pid=pid, limit=8)
        assert mods["count"] >= 1
        base_hex = mods["modules"][0]["base"]
        assert base_hex, "module base address missing"

        # exports: enumerateExports over a real module returns named symbols.
        # libc is present in the CPython child on Linux; tolerate its absence on
        # other platforms by only asserting the envelope shape when found.
        exports = client.exports(pid, mods["modules"][0]["name"], allowed_pid=pid, limit=4)
        assert isinstance(exports["found"], bool)
        assert isinstance(exports["exports"], list)

        # read: this is the call that broke on frida 17. Reading at a module base
        # must return exactly the bytes requested, proving
        # ptr(address).readByteArray(size) runs on the installed runtime.
        mem = client.memory_read(pid, int(base_hex, 16), 4, allowed_pid=pid)
        assert mem["encoding"] == "hex"
        assert len(mem["data"]) == 4 * 2
        if sys.platform.startswith("linux"):
            # The loaded image starts with the ELF magic; a real read returns it.
            assert mem["data"] == "7f454c46"

        # The per-session pid guard must still reject an unauthorized pid.
        with pytest.raises(FridaError) as guard:
            client.memory_read(pid, int(base_hex, 16), 4, allowed_pid=pid + 1)
        assert guard.value.code == "permission_denied"
    finally:
        proc.kill()
        proc.wait(timeout=5)
