"""Live frida gate: attach a real local process and exercise the read surface.

The frida backend had almost no real coverage -- only a frida.devices envelope
check -- so attach, modules, exports, memory.read, hook injection, and the
pid-authorization boundary all ran without a real frida runtime behind them.
That is how a memory.read that calls the frida-17-removed Memory.readByteArray
global shipped: nothing ever read a byte through real frida. frida attaches to
local processes on Linux (a self-spawned child is ptrace-able even under
ptrace_scope=1), so this spawns one, drives the client's local ops against it,
and asserts a real read returns the target's ELF magic -- the assertion that
reproduces that bug. It needs the frida module and a machine that permits the
attach; either absent, it skips (skip != pass).
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Iterator

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# The ELF identification bytes at the base of every module on Linux; reading
# them back proves memory.read returned the target's real memory.
_ELF_MAGIC_HEX = "7f454c46"


@pytest.fixture
def target_process() -> Iterator[subprocess.Popen[bytes]]:
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
    time.sleep(1.0)  # let the interpreter map its modules before we attach
    try:
        yield proc
    finally:
        # never let the target outlive the gate
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.integration
def test_frida_local_attach_read_surface(target_process: subprocess.Popen[bytes]) -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida module not installed — frida live Gate not run (skip != pass)")
    pid = target_process.pid

    # The attach itself decides whether this machine lets us ptrace the child.
    # A failure here is an environment limit, not a code fault, so skip; every
    # assertion after a successful attach is real.
    try:
        attached = client.attach(pid, allowed_pid=pid, timeout=30.0)
    except FridaError as exc:
        pytest.skip(f"frida cannot attach on this machine ({exc.code}) — skip != pass")
    assert attached["attached"] is True
    assert attached["pid"] == pid

    modules = client.modules(pid, allowed_pid=pid, limit=8)
    assert modules["count"] >= 1
    assert modules["total"] >= modules["count"]
    first = modules["modules"][0]
    assert first["name"]
    base = int(first["base"], 16)

    exports = client.exports(pid, first["name"], allowed_pid=pid, limit=5)
    # found means the module resolved on the target; the main executable does.
    assert exports["found"] is True
    assert exports["module"]

    # memory.read is the operation the frida-17 fix restored: every module on
    # Linux is ELF, so reading its base must return the ELF magic. Before the
    # fix this raised backend_error (Memory.readByteArray was gone in frida 17).
    read = client.memory_read(pid, base, 4, allowed_pid=pid)
    assert read["size"] == 4
    assert read["encoding"] == "hex"
    assert read["data"] == _ELF_MAGIC_HEX

    # A canned hook must compile and load, and honestly report that detaching
    # destroyed it (persisted False) rather than claiming a durable hook.
    hooked = client.hook_template(pid, "noop", allowed_pid=pid, timeout=30.0)
    assert hooked["loaded"] is True
    assert hooked["persisted"] is False

    # The authorization boundary: a pid that is not the session's allowed pid is
    # refused before any attach, on every local op.
    other = pid + 100000
    with pytest.raises(FridaError) as denied:
        client.attach(other, allowed_pid=pid, timeout=5.0)
    assert denied.value.code == "permission_denied"
    with pytest.raises(FridaError) as denied_modules:
        client.modules(other, allowed_pid=pid)
    assert denied_modules.value.code == "permission_denied"
