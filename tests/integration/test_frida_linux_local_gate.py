"""Frida Linux local gate: proof the frida backend instruments a live process.

The only frida live gate (``test_m11_frida_live_gate.py``) is Windows-only, so on
Linux -- frida's home platform -- nothing here proves the backend can actually
attach to a process and read it. The service-level frida ops resolve their
``allowed_pid`` from a running x64dbg dynamic session's debuggee pid, which does
not exist off Windows, so this gate drives ``FridaClient`` directly against a
process it spawns and controls, and asserts the *instrumented facts*, not merely
that a call returned:

  * ``attach`` returns a local-device probe attach for the target pid;
  * ``modules`` enumerates the target's loaded libraries (libc among them), each
    with a real base address and non-zero size;
  * ``exports`` resolves zlib's well-known symbols (inflate / deflate / crc32 /
    adler32 / zlibVersion), each with a real address;
  * ``memory_read`` at a module base returns the ELF magic ``7f 45 4c 46``;
  * the single-pid guard refuses a pid other than the session's with
    ``permission_denied``.

skip != pass: without the frida module the gate skips; if frida is present but
cannot instrument in this environment (a locked-down container with ptrace
restricted) it skips with that reason rather than reporting a pass.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import time
from collections.abc import Iterator

import pytest

from headless_re_mcp.backends.frida import FridaClient, FridaError

# This gate asserts Linux specifics (libc.so / libz.so module names, the ELF
# header magic). The Windows frida path is already covered by the Windows-only
# test_m11_frida_live_gate.py, so restrict this one to Linux rather than let its
# ELF assertions fail on a Windows integration run.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Frida Linux local gate asserts ELF/libc specifics — runs on Linux only",
)

# The target imports zlib (so libz is mapped) and sleeps so it stays alive for
# the probe; every test terminates it in a finally.
_TARGET_LIFETIME_S = 60
_SETTLE_S = 1.0
_ELF_MAGIC_HEX = "7f454c46"
_ZLIB_SYMBOLS = frozenset({"inflate", "deflate", "crc32", "adler32", "zlibVersion"})


def _client_or_skip() -> FridaClient:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida module not installed — Frida Linux local Gate not run (skip != pass)")
    return client


@contextlib.contextmanager
def _target() -> Iterator[int]:
    proc = subprocess.Popen(
        [sys.executable, "-c", f"import zlib, time; time.sleep({_TARGET_LIFETIME_S})"]
    )
    try:
        time.sleep(_SETTLE_S)
        yield proc.pid
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)
        if proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.kill()


def _attach_or_skip(client: FridaClient, pid: int) -> dict:
    try:
        return client.attach(pid, allowed_pid=pid)
    except FridaError as exc:
        pytest.skip(f"frida cannot instrument here ({exc.code}: {exc.message}) — skip != pass")


@pytest.mark.integration
def test_frida_instruments_a_live_process() -> None:
    client = _client_or_skip()
    with _target() as pid:
        attached = _attach_or_skip(client, pid)
        assert attached["attached"] is True
        assert attached["device"] == "local"
        assert attached["pid"] == pid

        modules = client.modules(pid, allowed_pid=pid, limit=128)
        assert modules["count"] > 0
        by_name = {m["name"]: m for m in modules["modules"]}

        libc = next((m for n, m in by_name.items() if n.startswith("libc.so")), None)
        assert libc is not None, sorted(by_name)
        assert libc["base"].startswith("0x")
        assert int(libc["base"], 16) > 0
        assert libc["size"] > 0

        # zlib is a small, stable module: all its exports fit under the cap, so a
        # named-symbol assertion is deterministic (libc's printf sits past the cap).
        libz_name = next((n for n in by_name if n.startswith("libz.so")), None)
        assert libz_name is not None, sorted(by_name)
        exports = client.exports(pid, libz_name, allowed_pid=pid, limit=256)
        assert exports["found"] is True
        names = {e["name"] for e in exports["exports"]}
        assert names >= _ZLIB_SYMBOLS, sorted(names)[:20]
        for entry in exports["exports"]:
            assert entry["address"].startswith("0x")

        # Reading a module's base must return the ELF header magic -- proof the
        # read reached the target's real address space, not a stub.
        read = client.memory_read(pid, int(libc["base"], 16), 4, allowed_pid=pid)
        assert read["encoding"] == "hex"
        assert read["data"] == _ELF_MAGIC_HEX


@pytest.mark.integration
def test_frida_refuses_a_pid_outside_the_session() -> None:
    """The single-pid guard must refuse a pid other than the session's debuggee."""
    client = _client_or_skip()
    with _target() as pid:
        # Prove instrumentation works here first, else skip rather than fail.
        _attach_or_skip(client, pid)
        with pytest.raises(FridaError) as excinfo:
            client.modules(pid + 1, allowed_pid=pid, limit=8)
        assert excinfo.value.code == "permission_denied"
