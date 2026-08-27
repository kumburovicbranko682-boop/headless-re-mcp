"""Live frida gate: attach to a real local process, list modules, read memory.

The frida line had no live coverage at all -- every frida test stubs the
runtime, so the attach/enumerate/read path was only ever exercised against a
fake. That is exactly where a frida-API drift hides: modern frida removed the
``Memory`` global, so the memory read had to move to ``NativePointer.readByteArray``
and nothing ran the real thing. This spawns a trivial long-lived child process,
attaches with frida, enumerates its modules and a module's exports, and reads
the first bytes at a module's load address -- which are always the ELF magic --
so the read path is proven end to end against a genuine target.

skip != pass: it skips when frida is not installed, or when the host's ptrace
policy refuses the attach (an environment limit, not a code fault).
"""

from __future__ import annotations

import subprocess
import sys
import time
from contextlib import suppress

import pytest

from headless_re_mcp.backends.frida import FridaClient, FridaError


def _frida_available() -> bool:
    return FridaClient().available


@pytest.mark.integration
def test_frida_attaches_lists_and_reads_a_live_process() -> None:
    if not _frida_available():
        pytest.skip("frida not installed — frida live gate not run (skip != pass)")
    client = FridaClient()
    # A trivial, long-lived local process to instrument. It is a child of this
    # test process, so attaching needs no elevated privilege under a normal
    # ptrace policy; frida injects, reads, and detaches each call.
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        time.sleep(0.7)  # let the interpreter finish mapping its modules
        pid = proc.pid
        try:
            attached = client.attach(pid, allowed_pid=pid)
        except FridaError as exc:
            pytest.skip(
                f"frida could not attach to a local process ({exc.code}) — "
                f"gate not run (skip != pass)"
            )
        assert attached["attached"] is True
        assert attached["device"] == "local"

        mods = client.modules(pid, allowed_pid=pid, limit=128)
        assert mods["count"] > 0
        names = [str(m["name"]) for m in mods["modules"]]
        assert any("libc" in name for name in names), names

        # A module with a real load address to read from, and libc for exports.
        base: int | None = None
        libc_name: str | None = None
        for mod in mods["modules"]:
            hex_base = str(mod["base"])
            if base is None and hex_base.startswith("0x") and int(hex_base, 16):
                base = int(hex_base, 16)
            if "libc" in str(mod["name"]):
                libc_name = str(mod["name"])
        assert base is not None
        assert libc_name is not None

        # exports of a module that has them: libc always exports symbols.
        exports = client.exports(pid, libc_name, allowed_pid=pid, limit=32)
        assert exports["found"] is True
        assert exports["count"] > 0
        assert all(entry["name"] and entry["address"] for entry in exports["exports"])

        # The point: read memory from the live process. Every loaded module
        # starts with the ELF magic, so this proves the read works and pins the
        # NativePointer-based read path (frida removed the Memory global) against
        # a real target instead of a stub.
        read = client.memory_read(pid, base, 4, allowed_pid=pid)
        assert read["encoding"] == "hex"
        assert bytes.fromhex(str(read["data"])) == b"\x7fELF"
    finally:
        proc.terminate()
        with suppress(Exception):
            proc.wait(timeout=5)


@pytest.mark.integration
def test_frida_hook_template_compiles_against_a_live_process() -> None:
    """hook_template really compiles+loads the script in the target, not a lookup.

    A template that referenced a frida API the runtime no longer has would fail
    to load; asserting the 'noop' template loads against a live process proves
    the compile/inject path works. An unknown template is a structured
    invalid_params that names the templates that do exist.
    """
    if not _frida_available():
        pytest.skip("frida not installed — frida live gate not run (skip != pass)")
    client = FridaClient()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        time.sleep(0.7)
        pid = proc.pid
        try:
            loaded = client.hook_template(pid, "noop", allowed_pid=pid)
        except FridaError as exc:
            pytest.skip(
                f"frida could not attach to a local process ({exc.code}) — "
                f"gate not run (skip != pass)"
            )
        assert loaded["loaded"] is True
        assert loaded["template"] == "noop"
        assert loaded["device"] == "local"

        with pytest.raises(FridaError) as info:
            client.hook_template(pid, "no-such-template", allowed_pid=pid)
        assert info.value.code == "invalid_params"
        assert "noop" in info.value.details.get("allowed", [])
    finally:
        proc.terminate()
        with suppress(Exception):
            proc.wait(timeout=5)


@pytest.mark.integration
def test_frida_attach_rejects_a_pid_outside_the_authorised_one() -> None:
    """The pid guard is a real check: attaching to a pid != allowed_pid is denied."""
    if not _frida_available():
        pytest.skip("frida not installed — frida live gate not run (skip != pass)")
    client = FridaClient()
    with pytest.raises(FridaError) as info:
        client.attach(1, allowed_pid=2)
    assert info.value.code == "permission_denied"
