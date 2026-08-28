"""Local Frida live gate: attach / modules / exports / hook on a spawned child.

Cross-platform counterpart to ``test_m11_frida_live_gate.py``, which probes
Windows-only modules (kernel32/ntdll) and is therefore force-skipped off
Windows. The ``FridaClient`` core paths -- the allow-set guard, attach, module
and export enumeration, and template injection -- are platform-neutral, and on
Linux they are the backbone of the Android dynamic line. This gate drives them
against a plain interpreter child on whatever platform runs it. skip != pass: it
skips when frida is absent or the host forbids attaching (locked-down ptrace),
never silently.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# Modules every supported host maps into a plain interpreter child: libc and the
# dynamic loader on Linux, kernel32 / ntdll on Windows. At least one must be
# present and export symbols, which is what makes the export read meaningful
# rather than a check that merely tolerates an empty list.
_SYSTEM_MODULE_MARKERS = (
    "libc",
    "ld-linux",
    "ld-musl",
    "kernel32",
    "ntdll",
)


@pytest.mark.integration
def test_frida_local_attach_modules_exports_hook() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — live Gate not run (skip≠pass)")

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.5)
        assert child.poll() is None, "child exited early"

        # The allow-set guard refuses a pid the session was not authorised for,
        # before any frida call touches the process.
        with pytest.raises(FridaError) as denied:
            client.modules(child.pid, allowed_pid=child.pid + 1, limit=4)
        assert denied.value.code == "permission_denied"

        try:
            attached = client.attach(child.pid, allowed_pid=child.pid)
        except FridaError as exc:
            # A host with restricted ptrace (yama scope, no CAP_SYS_PTRACE, a
            # hardened container) cannot attach at all. That is an environment
            # limit, not a regression -- report it as a skip, not a failure.
            pytest.skip(f"frida cannot attach here ({exc.code}: {exc.message}) — skip≠pass")
        assert attached.get("attached") is True
        assert attached.get("pid") == child.pid

        mods = client.modules(child.pid, allowed_pid=child.pid, limit=64)
        assert mods["count"] >= 1
        names = [str(module.get("name", "")) for module in mods["modules"]]
        assert any(names), "modules must carry names"

        target = next(
            (name for name in names if any(m in name.lower() for m in _SYSTEM_MODULE_MARKERS)),
            None,
        )
        assert target is not None, f"expected a system module among {names}"
        exports = client.exports(child.pid, target, allowed_pid=child.pid, limit=16)
        assert exports.get("found") is True
        assert exports.get("count", 0) >= 1
        assert isinstance(exports.get("exports"), list)

        hooked = client.hook_template(child.pid, "noop", allowed_pid=child.pid)
        assert hooked.get("loaded") is True
        # A probe injection detaches immediately, so it must report that nothing
        # stays hooked in the target rather than leaving an agent resident.
        assert hooked.get("persisted") is False
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
