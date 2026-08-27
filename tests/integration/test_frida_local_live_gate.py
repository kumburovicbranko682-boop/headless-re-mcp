"""Cross-platform Frida live gate: local attach/modules/exports/read/hook.

The Windows gate (``test_m11_frida_live_gate.py``) proves the same FridaClient
against a PE fixture and Windows system DLLs. This one exercises the identical
local contract on any OS by attaching to a portable child process we own, so
the dynamic-instrumentation line is verified off Windows too. Attaching to our
own child is what keeps it runnable unprivileged on ``ptrace_scope=1`` hosts;
where ptrace is locked down harder it skips rather than fails (skip != pass).
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# attach can legitimately be refused by the host kernel (no CAP_SYS_PTRACE,
# ptrace_scope=2, hardened container). Those are environment limits, not code
# faults, so we skip on them the same way we skip when frida is absent.
_ENV_LIMIT_CODES = {"backend_error", "timeout", "capability_unavailable"}


@pytest.mark.integration
def test_frida_local_live_attach_modules_exports_read_hook() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")

    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.5)
        assert proc.poll() is None, "helper process exited early"

        # Authorization is enforced before any attach: a pid outside the
        # session's allow-set is refused, not silently probed.
        denied = None
        try:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        try:
            attached = client.attach(proc.pid, allowed_pid=proc.pid)
        except FridaError as exc:
            if exc.code in _ENV_LIMIT_CODES:
                pytest.skip(f"frida cannot attach to a local process here: {exc.message}")
            raise
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid

        mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=16)
        assert mods["count"] >= 1
        assert mods["total"] >= mods["count"]
        assert all(isinstance(m.get("name"), str) and m["name"] for m in mods["modules"])
        assert all(m.get("base") for m in mods["modules"])

        # Pick a loaded module that actually exports symbols rather than
        # hardcoding libc / kernel32 — keeps the assertion OS-neutral.
        with_exports = None
        for module in mods["modules"]:
            exports = client.exports(
                proc.pid, module["name"], allowed_pid=proc.pid, limit=8
            )
            if exports.get("found") and exports.get("count", 0) >= 1:
                with_exports = (module, exports)
                break
        assert with_exports is not None, "expected at least one module with exports"
        module, exports = with_exports
        assert isinstance(exports["exports"], list)
        assert all(e.get("name") and e.get("address") for e in exports["exports"])

        # Read at the module's load address: this is the regression that the
        # removed Memory.readByteArray global used to break on frida 17.
        base = int(str(module["base"]), 16)
        mem = client.memory_read(proc.pid, base, 8, allowed_pid=proc.pid)
        assert mem["encoding"] == "hex"
        assert mem["size"] == 8
        assert len(mem["data"]) == 16
        assert bytes.fromhex(mem["data"])  # decodes cleanly to 8 bytes

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked.get("loaded") is True
        assert hooked.get("persisted") is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
