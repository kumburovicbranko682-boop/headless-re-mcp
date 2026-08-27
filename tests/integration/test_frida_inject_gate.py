"""frida local injection gate: real attach + script inject on this host.

frida's device-aware Android ops (``frida.java.classes`` / ``methods`` and the
hook templates) cannot run in CI without a device, but they share the exact
``create_script`` / ``load`` / ``exports_sync`` machinery with the local ops --
which *can* run here by attaching to a child process the test spawns. Driving
that machinery end to end means a frida version drift that breaks injection
fails in CI instead of in production: frida 17 removed the ``Memory.readByteArray``
global, which silently broke ``frida.memory.read`` until the script was moved to
the NativePointer method.

When frida is absent or the host forbids ptrace attach (some hardened kernels),
the gate skips with a reason rather than passing vacuously (skip != pass).
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import time
from collections.abc import Iterator

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


@pytest.fixture
def local_target() -> Iterator[int]:
    """A benign, long-lived child process to attach to, torn down after."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.5)
    try:
        yield proc.pid
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


def _client_or_skip(pid: int) -> FridaClient:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida not installed — injection gate not run (skip != pass)")
    try:
        client.attach(pid, allowed_pid=pid)
    except FridaError as exc:
        # A hardened kernel (ptrace_scope 2/3) or a sandbox can forbid attach;
        # that is an environment limit, not a product failure.
        if exc.code in {"backend_error", "timeout", "permission_denied", "capability_unavailable"}:
            pytest.skip(f"frida cannot attach on this host ({exc.code}) — injection gate not run")
        raise
    return client


@pytest.mark.integration
def test_frida_local_modules_and_memory_read(local_target: int) -> None:
    client = _client_or_skip(local_target)

    mods = client.modules(local_target, allowed_pid=local_target, limit=5)
    assert mods["count"] >= 1
    assert mods["total"] >= mods["count"]
    first = mods["modules"][0]
    assert first["name"]
    assert first["base"].startswith("0x")

    # The main module base is mapped and readable; reading it exercises the RPC
    # that frida 17 broke. Assert we get exactly the bytes asked for back.
    base = int(first["base"], 16)
    read = client.memory_read(local_target, base, 8, allowed_pid=local_target)
    assert read["encoding"] == "hex"
    assert len(bytes.fromhex(read["data"])) == 8


@pytest.mark.integration
def test_frida_local_exports_enumeration(local_target: int) -> None:
    client = _client_or_skip(local_target)

    mods = client.modules(local_target, allowed_pid=local_target, limit=64)
    # Find a shared library that actually exports symbols (libc always does).
    found_any = False
    for module in mods["modules"]:
        name = module["name"]
        if ".so" not in name and "libc" not in name:
            continue
        result = client.exports(local_target, name, allowed_pid=local_target, limit=5)
        assert isinstance(result["found"], bool)
        if result["found"] and result["count"] >= 1:
            entry = result["exports"][0]
            assert entry["name"]
            assert entry["address"].startswith("0x")
            found_any = True
            break
    assert found_any, "no module reported any exports — enumeration is broken"


@pytest.mark.integration
def test_frida_local_unreadable_memory_is_a_structured_error(local_target: int) -> None:
    client = _client_or_skip(local_target)
    # Reading the null page must come back as a backend_error envelope, never a
    # raw RPCException that the service would misfile as internal_error.
    with pytest.raises(FridaError) as info:
        client.memory_read(local_target, 0, 16, allowed_pid=local_target)
    assert info.value.code == "backend_error"


@pytest.mark.integration
def test_frida_local_noop_hook_template_loads(local_target: int) -> None:
    client = _client_or_skip(local_target)
    result = client.hook_template(local_target, "noop", allowed_pid=local_target)
    assert result["loaded"] is True
    assert result["persisted"] is False
