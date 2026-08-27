"""Frida local-process live gate: attach + enumerate + read a real process.

Every other Frida test either mocks the ``frida`` module or is the Windows
PE-session gate (``test_m11_frida_live_gate.py``), so the cross-platform enum
path -- ``modules`` / ``exports`` / ``memory.read`` -- had no live coverage.
That is exactly where a frida-version regression hid: the enum script read
memory with the long-removed ``Memory.readByteArray`` global, which throws
"not a function" on frida >=14, so ``memory.read`` failed on every modern
frida while the mocked tests stayed green.

Frida can inject into an ordinary local process, so this needs no device or
emulator: it spawns a short-lived child, attaches, and asserts on real module
and export data. It skips honestly when frida is absent or the host forbids
ptrace injection (hardened containers, ``ptrace_scope``), because a gate that
cannot attach proves nothing -- skip != pass.
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

# Executable-image magic numbers, as the lowercase hex a memory read returns.
# ELF (Linux), Mach-O thin/fat (macOS), and PE's "MZ" stub (Windows) cover
# every platform frida injects into; reading 4 bytes at a module base must land
# on one of these, which is the concrete guard for the readByteArray fix.
_IMAGE_MAGICS = (
    "7f454c46",  # ELF
    "feedface",  # Mach-O 32-bit
    "cefaedfe",  # Mach-O 32-bit, byte-swapped
    "feedfacf",  # Mach-O 64-bit
    "cffaedfe",  # Mach-O 64-bit, byte-swapped
    "cafebabe",  # Mach-O universal (fat)
    "4d5a",  # PE/DOS "MZ"
)


@dataclass
class _Harness:
    client: FridaClient
    pid: int
    modules: dict
    export_module: str
    export_base: str


def _pick_exporting_module(client: FridaClient, pid: int, modules: dict) -> tuple[str, str] | None:
    """First module that actually resolves exports, with its base address.

    The main executable often exports nothing, so the export and memory checks
    target whichever mapped image has a symbol table (libc, in practice).
    """
    for entry in modules["modules"]:
        name = entry.get("name") or ""
        base = entry.get("base") or ""
        if not name or not base:
            continue
        try:
            result = client.exports(pid, name, allowed_pid=pid, limit=4)
        except FridaError:
            continue
        if result.get("found") and result.get("count", 0) >= 1:
            return name, base
    return None


@pytest.fixture(scope="module")
def _harness() -> Iterator[_Harness]:
    client = FridaClient()
    if not client.available:
        pytest.skip("frida Python module not installed — Frida Local Gate not run (skip != pass)")
    # A plain sleeping child: portable, cheap, and guaranteed to map libc so the
    # export/read checks have a real symbol table to look at.
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3600)"])
    # Give the interpreter a moment to map its shared libraries before we
    # enumerate them; without this the module list can be caught mid-startup.
    time.sleep(0.7)
    pid = child.pid
    try:
        try:
            modules = client.modules(pid, allowed_pid=pid, limit=256)
        except FridaError as exc:
            pytest.skip(
                f"frida cannot attach to a local process here ({exc.code}: {exc.message}); "
                "likely ptrace/hardening — Frida Local Gate not run (skip != pass)"
            )
        picked = _pick_exporting_module(client, pid, modules)
        if picked is None:
            pytest.skip(
                "no local module exposed exports to frida — Frida Local Gate not run "
                "(skip != pass)"
            )
        name, base = picked
        harness = _Harness(
            client=client, pid=pid, modules=modules, export_module=name, export_base=base
        )
        yield harness
    finally:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()


@pytest.mark.integration
def test_modules_enumerates_the_live_process(_harness: _Harness) -> None:
    modules = _harness.modules
    assert modules["count"] >= 1
    assert modules["total"] >= modules["count"]
    assert isinstance(modules["has_more"], bool)
    # Real entries, not empty placeholders: a name and a hex base for each.
    for entry in modules["modules"]:
        assert entry["name"]
        assert entry["base"].startswith("0x")
        assert entry["size"] >= 0


@pytest.mark.integration
def test_exports_returns_real_symbols(_harness: _Harness) -> None:
    result = _harness.client.exports(
        _harness.pid, _harness.export_module, allowed_pid=_harness.pid, limit=8
    )
    assert result["found"] is True
    assert result["module"]
    assert result["count"] >= 1
    assert isinstance(result["has_more"], bool)
    for item in result["exports"]:
        assert item["name"]
        assert item["address"].startswith("0x")


@pytest.mark.integration
def test_memory_read_returns_the_image_header(_harness: _Harness) -> None:
    # Reading a module base is the concrete regression guard: the enum script
    # used to call the removed Memory.readByteArray and throw, so this is the
    # byte that proves memory.read works on modern frida.
    result = _harness.client.memory_read(
        _harness.pid, int(_harness.export_base, 16), 8, allowed_pid=_harness.pid
    )
    assert result["size"] == 8
    assert result["encoding"] == "hex"
    assert len(result["data"]) == 16  # eight bytes, two hex chars each
    assert result["data"].startswith(_IMAGE_MAGICS), result["data"]


@pytest.mark.integration
def test_attach_probe_reports_the_session(_harness: _Harness) -> None:
    result = _harness.client.attach(_harness.pid, allowed_pid=_harness.pid)
    assert result["attached"] is True
    assert result["pid"] == _harness.pid
    assert result["device"] == "local"


@pytest.mark.integration
def test_hook_template_loads_the_noop_script(_harness: _Harness) -> None:
    result = _harness.client.hook_template(_harness.pid, "noop", allowed_pid=_harness.pid)
    assert result["loaded"] is True
    assert result["template"] == "noop"
    # The probe detaches, so nothing stays hooked — the reply must say so.
    assert result["persisted"] is False


@pytest.mark.integration
def test_pid_guard_rejects_an_unauthorized_target(_harness: _Harness) -> None:
    # The allow-pid check must gate a live call, not only the mocked unit path:
    # a mismatched allowed_pid is refused before any injection happens.
    with pytest.raises(FridaError) as caught:
        _harness.client.modules(_harness.pid, allowed_pid=_harness.pid + 1, limit=4)
    assert caught.value.code == "permission_denied"
