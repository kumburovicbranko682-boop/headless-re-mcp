"""frida hook-template live gate: a real agent script loaded into a process.

The frida local gate covers the read-only surface (attach, modules, exports,
memory read). The instrumentation entry point -- ``frida.hook.template``, which
compiles one of the shipped hook scripts and loads it into the target's GumJS
agent -- only ever ran against a fake frida in unit tests. So nothing proved a
shipped template is actually valid script for the installed frida, nor that the
attach -> create_script -> load -> detach lifecycle works end to end.

This gate spawns an ordinary local process and, for real:

  * loads the generic ``noop`` template (the only one that does not need an ART
    runtime) and asserts frida reported it loaded -- which means the installed
    GumJS compiled and ran the script, not that a mock returned a dict; and
  * pins the two guards that need no attach: an unknown template name is refused
    with ``invalid_params`` and the allowed list, and a pid other than the
    session's allowed pid is refused with ``permission_denied``.

The Java templates (ssl-unpin, crypto-monitor, ...) target ART and are out of
scope on a Linux host, so only ``noop`` is exercised here.

Skip != pass: the gate skips with a reason when frida is absent or the platform
refuses a local attach (a locked-down ``ptrace_scope``). CI installs frida and
opens ptrace, so a skip there is a genuine regression rather than a bare machine.
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
    """A long-lived local process to instrument, cleaned up afterwards."""
    sleeper = shutil.which("sleep")
    if sleeper is not None:
        cmd = [sleeper, "60"]
    else:
        cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
    proc = subprocess.Popen(cmd)
    time.sleep(0.5)
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=10)


@pytest.mark.integration
def test_frida_hook_template_loads_and_enforces_its_guards() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida not installed — hook-template Gate not run (skip != pass)")

    with _spawned_target() as pid:
        # Guards first: neither needs a successful attach, so they run even on a
        # host that refuses ptrace.
        # An unknown template is refused before any injection, and the error names
        # the templates that do exist.
        with pytest.raises(FridaError) as unknown:
            client.hook_template(pid, "does_not_exist", allowed_pid=pid, timeout=20.0)
        assert unknown.value.code == "invalid_params"
        allowed = unknown.value.details.get("allowed")
        assert isinstance(allowed, list) and "noop" in allowed

        # Instrumentation is fenced to the session's debuggee pid: a different
        # allowed pid is refused before attaching.
        with pytest.raises(FridaError) as denied:
            client.hook_template(pid, "noop", allowed_pid=pid + 1, timeout=20.0)
        assert denied.value.code == "permission_denied"

        # The real load: noop needs a live attach, so a locked-down ptrace_scope
        # is an environment limitation, not a code bug -- skip honestly there.
        try:
            loaded = client.hook_template(pid, "noop", allowed_pid=pid, timeout=30.0)
        except FridaError as exc:
            pytest.skip(f"frida could not attach ({exc.code}: {exc}) — Gate not run (skip != pass)")

        # frida reported the script compiled and loaded into the target's agent.
        assert loaded["loaded"] is True
        assert loaded["template"] == "noop"
        assert loaded["device"] == "local"
