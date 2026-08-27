"""M11 Frida local gate: attach/modules/exports/memory/hook against a real child.

The sibling ``test_m11_frida_live_gate`` drives a Windows PE fixture, so off
Windows it can only skip. But frida's *local* operations attach to any process
on this machine by pid, and that is exactly the path a PE session's ``frida.*``
tools take on the analyst's own box. This gate exercises that path against a
real Linux child process -- no Android device, no debug session, no fixture --
so the frida local surface is actually covered where CI runs, instead of being
a Windows-only skip that reads as a pass.

Local frida injection uses ptrace. GitHub's Ubuntu runners ship
``kernel.yama.ptrace_scope=1`` (a tracer may only attach to its descendants,
and frida's injector is a sibling of the target, not its parent), so the CI
lane relaxes it to 0 before this runs. Where the kernel still forbids injection
this skips with the scope value named, rather than reporting a frida regression
that is really a sandbox policy -- and never silently passes.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

_PTRACE_SCOPE = Path("/proc/sys/kernel/yama/ptrace_scope")
# The ELF magic every shared object and executable carries at file offset 0,
# which is what the first mapped page of a module base holds. Reading it back
# through frida proves the bytes came from the target's real address space and
# not from a stubbed reply.
_ELF_MAGIC_HEX = "7f454c46"
# Substrings that mark "the kernel refused the injection" rather than "frida is
# broken": a locked-down ptrace_scope, a missing capability, or a helper that
# could not seize the target. Anything else past a failed attach is a real bug.
_INJECTION_DENIED_MARKERS = (
    "ptrace",
    "permission",
    "operation not permitted",
    "not permitted",
    "unable to access",
    "unable to attach",
    "access denied",
    "seccomp",
)


def _ptrace_scope() -> str:
    try:
        return _PTRACE_SCOPE.read_text(encoding="utf-8").strip()
    except OSError:
        return "unset"


def _looks_like_injection_denied(exc: FridaError) -> bool:
    blob = f"{exc.code} {exc.message} {exc.details}".lower()
    return any(marker in blob for marker in _INJECTION_DENIED_MARKERS)


def _spawn_target() -> subprocess.Popen[bytes]:
    """A long-lived local child that maps libc, so modules/exports have content.

    The interpreter under test is guaranteed present and dynamically linked, so
    ``libc``/``ld`` show up as real modules with real export tables -- no need
    for a compiled fixture that would have to be shipped per platform.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="local frida gate targets Linux; Windows PE is covered by the live gate,"
    " and macOS local injection needs root/entitlements (skip≠pass)",
)
def test_m11_frida_local_attach_modules_exports_memory_hook() -> None:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — local gate not run (skip≠pass)")

    proc = _spawn_target()
    try:
        time.sleep(0.6)
        assert proc.poll() is None, "target interpreter exited before frida could attach"

        # The single-pid boundary is the whole security contract of the local
        # path: a caller may only touch the pid it was authorized for.
        with pytest.raises(FridaError) as denied:
            client.modules(proc.pid, allowed_pid=proc.pid + 1, limit=4)
        assert denied.value.code == "permission_denied"

        try:
            attached = client.attach(proc.pid, allowed_pid=proc.pid)
        except FridaError as exc:
            if _looks_like_injection_denied(exc):
                pytest.skip(
                    "kernel forbids local frida injection "
                    f"(yama ptrace_scope={_ptrace_scope()}): {exc.message} — skip≠pass"
                )
            raise
        assert attached["attached"] is True
        assert attached["pid"] == proc.pid
        assert "detached" in str(attached.get("note", "")).lower()

        # Paging: asking for two of many must say so, or a caller reads the
        # first page as the whole module list.
        page = client.modules(proc.pid, allowed_pid=proc.pid, limit=2)
        assert page["count"] == 2
        assert page["total"] >= 3
        assert page["has_more"] is True

        listing = client.modules(proc.pid, allowed_pid=proc.pid, limit=256)
        assert listing["count"] == listing["total"]
        assert listing["has_more"] is False
        libc = next(
            (
                m
                for m in listing["modules"]
                if "libc" in str(m.get("name", "")).lower()
            ),
            None,
        )
        assert libc is not None, f"no libc among modules: {[m['name'] for m in listing['modules']]}"
        assert libc["base"], "module base address is empty"
        assert libc["path"], "module path is empty"

        exports = client.exports(proc.pid, str(libc["name"]), allowed_pid=proc.pid, limit=3)
        assert exports["found"] is True
        assert exports["module"] == libc["name"]
        assert exports["base"] == libc["base"]
        assert exports["count"] == 3
        assert exports["has_more"] is True
        first = exports["exports"][0]
        assert first["name"], "export has no name"
        assert first["address"].startswith("0x"), f"export address not hex: {first['address']}"
        assert first["type"], "export has no type"

        # A module that is not loaded must read as absent, not as an empty
        # export table on a module that exists.
        missing = client.exports(
            proc.pid, "definitely_not_a_real_module.so", allowed_pid=proc.pid, limit=3
        )
        assert missing["found"] is False
        assert missing["count"] == 0

        # Real memory: the first four bytes at a module base are the ELF magic.
        mem = client.memory_read(proc.pid, int(str(libc["base"]), 16), 4, allowed_pid=proc.pid)
        assert mem["encoding"] == "hex"
        assert mem["size"] == 4
        assert mem["data"] == _ELF_MAGIC_HEX, f"expected ELF magic, got {mem['data']}"

        hooked = client.hook_template(proc.pid, "noop", allowed_pid=proc.pid)
        assert hooked["loaded"] is True
        # The probe destroys itself on detach: it must say so rather than leave a
        # caller believing a hook outlived the call.
        assert hooked["persisted"] is False
        assert hooked["note"]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
