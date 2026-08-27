"""frida live gate: real instrumentation of a local process on Linux.

frida is cross-platform and can attach to a process on the local device, which
is exactly the path the backend uses to serve a PE debuggee on the same machine
(``FridaClient.attach`` and friends all go through ``frida.attach`` on the local
device). Every other frida test only asserted graceful degradation when frida
was absent, so nothing ever ran an attach -- which is how a dead memory-read
path survived (the script used ``Memory.readByteArray``, removed from modern
frida's GumJS, so every read raised "not a function").

This gate spawns an ordinary local process and drives the generic (non-Java)
operations for real: attach, enumerate modules, enumerate a module's exports,
and read memory at a module base (which must be the ELF magic). The Java hook
templates need an ART runtime, so they are out of scope here.

Skip != pass: the gate skips with a reason when frida is absent or the platform
refuses a local attach (a locked-down ``ptrace_scope``). CI installs frida and
opens ptrace, so a skip there is a genuine regression rather than a bare
machine.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


@contextmanager
def _spawned_target() -> Iterator[int]:
    """A long-lived local process to attach to, cleaned up afterwards."""
    sleeper = shutil.which("sleep")
    if sleeper is not None:
        cmd = [sleeper, "60"]
    else:
        cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
    proc = subprocess.Popen(cmd)
    # Give the loader a moment to map libc before we enumerate modules.
    time.sleep(0.5)
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=10)


@pytest.mark.integration
def test_frida_attaches_to_a_local_process_and_reads_it() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida not installed — local live Gate not run (skip != pass)")

    with _spawned_target() as pid:
        try:
            attached = client.attach(pid, allowed_pid=pid, timeout=30.0)
        except FridaError as exc:
            # A restricted ptrace_scope refuses attach to a sibling; that is an
            # environment limitation, not a code bug, so skip honestly. CI opens
            # ptrace, so it will not land here.
            pytest.skip(f"frida could not attach ({exc.code}: {exc}) — Gate not run (skip != pass)")

        assert attached["attached"] is True
        assert attached["device"] == "local"

        modules = client.modules(pid, allowed_pid=pid, limit=128)
        assert modules["total"] >= 1
        names = [m["name"] for m in modules["modules"]]
        libc = next((m for m in modules["modules"] if "libc" in m["name"]), None)
        assert libc is not None, f"expected a libc module among {names}"

        exports = client.exports(pid, libc["name"], allowed_pid=pid, limit=512)
        assert exports["found"] is True
        # libc exports far more than a handful of symbols; a real enumeration
        # returns a full page with names and addresses, not an empty stub.
        assert exports["count"] >= 100
        assert all(item["name"] and item["address"] for item in exports["exports"])

        # Reading the module base must return the ELF magic (\x7fELF); this is
        # the path that was silently broken until the readByteArray fix.
        magic = client.memory_read(pid, int(libc["base"], 16), 4, allowed_pid=pid)
        assert magic["data"] == "7f454c46"


@pytest.mark.integration
def test_frida_attach_is_limited_to_the_allowed_pid() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida not installed — local live Gate not run (skip != pass)")
    # The guard runs before any attach, so this is deterministic wherever frida
    # imports: attaching to anything but the session's debuggee is refused.
    with pytest.raises(FridaError) as info:
        client.attach(4321, allowed_pid=1234, timeout=5.0)
    assert info.value.code == "permission_denied"
