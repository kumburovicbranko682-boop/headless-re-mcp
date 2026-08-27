"""Frida local gate: attach/modules/exports/read/hook against a child we own.

The existing M11 Frida gate is pinned to a Windows PE fixture and probes Windows
system DLLs, so it always skips off Windows and never exercised the client on the
Linux CI host. Frida can inject into a local child process on Linux too (ptrace
of a direct descendant is allowed even under yama ptrace_scope=1), so this drives
the same client surface -- attach, module enumeration, export enumeration, a
memory read, and a probe hook -- against a Python interpreter we spawn ourselves.

It caught a real regression: frida 17 removed the free ``Memory.readByteArray``
the enumeration script used, so ``frida.read`` raised "not a function" against
every frida >= 17 target; the read assertion below fails without the pointer-form
fix. It skips (never passes) only when frida is absent or the kernel refuses the
ptrace attach outright.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


@pytest.mark.integration
def test_frida_local_attach_enumerate_read_hook() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — local Gate not run (skip != pass)")

    # A long-lived child we own; frida injects its agent into this process.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.4)
        assert child.poll() is None, "sleeper child exited early"
        pid = child.pid

        # Pure-Python authorization guard: a pid outside the session's allow-set
        # is refused before any frida call, so this holds even where ptrace does
        # not. Anything other than permission_denied here is a real defect.
        denied: FridaError | None = None
        try:
            client.modules(pid, allowed_pid=pid + 1, limit=4)
        except FridaError as exc:
            denied = exc
        assert denied is not None and denied.code == "permission_denied"

        try:
            attached = client.attach(pid, allowed_pid=pid)
        except FridaError as exc:
            if exc.code == "permission_denied":
                raise
            # Injection itself failed: a hardened kernel (ptrace_scope 2/3) or a
            # missing helper. That is an environment limit, not a product bug, so
            # skip honestly rather than reporting a red gate.
            pytest.skip(
                f"frida could not attach locally ({exc.code}: {exc.message}) — "
                "ptrace likely restricted (skip != pass)"
            )
        assert attached.get("attached") is True
        assert attached.get("pid") == pid

        modules = client.modules(pid, allowed_pid=pid, limit=64)
        assert modules["count"] >= 1
        assert any(m.get("name") for m in modules["modules"])

        # Find any loaded module that actually exposes exports (libc / the
        # interpreter always do) and prove the export table decodes.
        exporting = None
        for module in modules["modules"]:
            result = client.exports(pid, module["name"], allowed_pid=pid, limit=8)
            if result.get("found") and result.get("count", 0) >= 1:
                exporting = (module, result)
                break
        assert exporting is not None, "no module exposed enumerable exports"
        module, result = exporting
        assert all(item.get("name") for item in result["exports"])

        # Read bytes straight from a mapped module base. Without the frida-17
        # readByteArray fix this raises backend_error instead of returning data.
        base = int(module["base"], 16)
        read = client.memory_read(pid, base, 16, allowed_pid=pid)
        assert read["size"] == 16
        assert len(read["data"]) == 32  # 16 bytes, hex-encoded

        # On Linux the main image base is the ELF header, a deterministic anchor
        # proving the read returned the process's real memory, not zeros.
        if sys.platform.startswith("linux"):
            main = next(
                (m for m in modules["modules"] if not m["name"].endswith(".so")
                 and ".so." not in m["name"]),
                modules["modules"][0],
            )
            head = client.memory_read(pid, int(main["base"], 16), 4, allowed_pid=pid)
            assert head["data"] == "7f454c46", f"expected ELF magic, got {head['data']}"

        hooked = client.hook_template(pid, "noop", allowed_pid=pid)
        assert hooked.get("loaded") is True
        # The probe hook is torn down with the session; the client must say so.
        assert hooked.get("persisted") is False
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
