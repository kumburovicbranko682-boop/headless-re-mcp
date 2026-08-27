"""Live Frida gate on a local POSIX process — the non-Windows counterpart.

``test_m11_frida_live_gate`` only runs where a Windows PE fixture and
kernel32/ntdll are present, so on Linux the whole Frida line -- local inject,
module and export enumeration, the permission gate, script load -- had no live
coverage and every assertion about it rested on unit mocks. This drives the
real ``FridaClient`` against a spawned child (the Python interpreter itself,
which is always present and dynamically linked to libc), so the injector, the
enumerate script over RPC, and the hook template all execute for real.

Deterministic and self-contained: no device, no network, no fixture to build.
skip != pass when the frida module is missing or the platform is not POSIX
(Windows is covered by the PE gate).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# Frida injects via ptrace; a locked-down sandbox (yama ptrace_scope, seccomp,
# no CAP_SYS_PTRACE) refuses that at the OS layer. That is the environment
# saying "not here", not the backend being wrong, so it is an honest skip --
# distinct from a contract break, which still fails. The phrases are frida's
# own wording for the refusal.
_PTRACE_BLOCKED = ("system restrictions", "ptrace_scope", "operation not permitted")


def _is_sandbox_ptrace_refusal(exc: FridaError) -> bool:
    blob = f"{exc.message} {exc.details}".lower()
    return any(needle in blob for needle in _PTRACE_BLOCKED)


@pytest.mark.integration
def test_frida_local_attach_modules_exports_and_hook() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — local Gate not run (skip != pass)")
    if os.name != "posix":
        pytest.skip("local POSIX inject gate; Windows is covered by the PE frida gate")

    # A long-lived, dynamically linked child: the interpreter is guaranteed to
    # be here and to load libc, and killing it cannot disturb the test process.
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.5)
        assert proc.poll() is None, "child exited before frida could attach"

        # The allow-set is enforced before anything is injected: a pid the
        # session did not authorize must be refused, not attached.
        denied: FridaError | None = None
        try:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        try:
            attached = client.attach(proc.pid, allowed_pid=proc.pid)
        except FridaError as exc:
            if _is_sandbox_ptrace_refusal(exc):
                pytest.skip(f"sandbox refused ptrace inject: {exc.message} (skip != pass)")
            raise
        assert attached.get("attached") is True
        assert attached.get("pid") == proc.pid

        mods = client.modules(proc.pid, allowed_pid=proc.pid, limit=64)
        assert mods["count"] >= 1
        assert mods["total"] >= mods["count"]
        names = [str(m["name"]) for m in mods["modules"]]
        assert all(names), "a module came back with an empty name"
        # Every dynamically linked ELF maps libc; use it as the export target.
        libc = next((n for n in names if "libc" in n.lower()), None)
        assert libc is not None, f"libc not among frida modules: {names}"

        exports = client.exports(proc.pid, libc, allowed_pid=proc.pid, limit=64)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 1
        assert all(str(e.get("name")) for e in exports["exports"]), "empty export name"
        assert all(str(e.get("address")) for e in exports["exports"]), "empty export address"

        # The canned "noop" script must compile and load in the target.
        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked.get("loaded") is True
        assert hooked.get("persisted") is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
