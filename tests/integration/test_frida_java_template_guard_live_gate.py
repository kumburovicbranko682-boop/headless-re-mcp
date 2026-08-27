"""frida java-template target guard: refuse an Android hook off ART, for real.

The canned ``android_*`` hook templates run inside ``Java.perform`` and wrap
their ``Java.use`` calls in a ``try/catch``. On a target with no ART runtime the
Java lookup throws, the catch swallows it, and the script still loads clean --
so frida reports ``loaded: True`` for a hook that installed nothing. An early
comment in the client even claimed the load *raises* off ART and the caller gets
a ``backend_error``; empirically it does neither. An unattended agent that loaded
``android_ssl_unpin`` against a desktop process would then sit waiting for a
bypass that was never wired in.

The client now probes the attached target for a live Java VM before loading one
of those templates and refuses with ``target_mismatch`` when it is absent. This
gate proves that against a real frida agent -- not a mock returning a dict:

  * ``noop`` (no ART needed) still loads end to end, so the guard did not break
    the ordinary path;
  * ``android_ssl_unpin`` and ``android_crypto_monitor`` are refused with
    ``target_mismatch`` on this non-ART Linux target, which means the Java probe
    actually ran in the target and reported no VM; and
  * the two attach-free guards still hold: an unknown template is ``invalid_params``
    and a pid other than the session's is ``permission_denied``.

Skip != pass: the gate skips with a reason when frida is absent or the host
refuses a local attach (locked-down ``ptrace_scope``). CI installs frida and
opens ptrace, so a skip there is a real regression, not a bare machine.
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
    """A long-lived local (non-ART) process to attach to, cleaned up afterwards."""
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
def test_java_template_is_refused_on_a_non_art_target() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida not installed — java-template guard gate not run (skip != pass)")

    with _spawned_target() as pid:
        # Attach-free guards first: neither reaches the Java probe, so they hold
        # even on a host that refuses ptrace.
        with pytest.raises(FridaError) as unknown:
            client.hook_template(pid, "does_not_exist", allowed_pid=pid, timeout=20.0)
        assert unknown.value.code == "invalid_params"

        with pytest.raises(FridaError) as denied:
            client.hook_template(pid, "android_ssl_unpin", allowed_pid=pid + 1, timeout=20.0)
        assert denied.value.code == "permission_denied"

        # The rest needs a live attach: a locked-down ptrace_scope is an
        # environment limit, not a code bug -- skip honestly there.
        try:
            loaded = client.hook_template(pid, "noop", allowed_pid=pid, timeout=30.0)
        except FridaError as exc:
            pytest.skip(f"frida could not attach ({exc.code}: {exc}) — gate not run (skip != pass)")

        # The ordinary path still works: noop needs no ART and loads for real.
        assert loaded["loaded"] is True
        assert loaded["template"] == "noop"

        # The fix: Java templates are refused because the target has no ART
        # runtime. A load that returned loaded:True here would be the false green
        # this guard exists to stop.
        for template in ("android_ssl_unpin", "android_crypto_monitor", "android_root_bypass"):
            with pytest.raises(FridaError) as mismatch:
                client.hook_template(pid, template, allowed_pid=pid, timeout=30.0)
            assert mismatch.value.code == "target_mismatch", template
            assert mismatch.value.details.get("template") == template
            named = mismatch.value.details.get("java_templates")
            assert isinstance(named, list) and template in named
