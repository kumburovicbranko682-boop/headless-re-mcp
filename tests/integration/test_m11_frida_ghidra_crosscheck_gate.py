"""M11 dynamic<->static gate: Frida's runtime symbol agrees with Ghidra.

The Frida<->r2 gate cross-checks bytes; this ties the dynamic line to the
*decompiler*. Frida resolves a function's address in a live process, Ghidra
recovers that same function statically and decompiles its logic, and this gate
asserts the two agree on where the function is -- cross-checked against the ELF
symbol table as independent ground truth -- while Ghidra proves what it does.

The fixture is built ``-no-pie`` so the load address is fixed: the runtime
address Frida reports, the entry Ghidra recovers and the symbol table value all
coincide, with no base arithmetic to get wrong. That exact coincidence is the
point -- if dynamic resolution and static analysis disagreed on a function's
location an agent pivoting between them would be misled. skip != pass when
frida, Ghidra or a C compiler / nm is missing.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.backends.ghidra.client import GhidraClient

_SRC = r"""
#include <unistd.h>
int gate_reveal(int x) { return (x ^ 0x41) + 7; }
int main(void) { sleep(30); return gate_reveal(0); }
"""
_NM_LINE = re.compile(r"^([0-9a-fA-F]+)\s+[TtWw]\s+gate_reveal$")
_ANALYZE_TIMEOUT_S = 300.0


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def _build_fixed_address_exe(dest: Path) -> Path | None:
    compiler = _compiler()
    if compiler is None:
        return None
    src = dest / "gate.c"
    src.write_text(_SRC, encoding="utf-8")
    exe = dest / "gate_exe"
    # -no-pie pins the load address; -rdynamic publishes gate_reveal in .dynsym
    # so frida's enumerateExports can see it. The premise needs a non-PIE image,
    # so there is no PIE fallback -- a toolchain that refuses it skips instead.
    try:
        subprocess.run(  # noqa: S603 - fixed args, local compiler
            [compiler, "-O0", "-no-pie", "-fno-pic", "-rdynamic", "-o", str(exe), str(src)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return exe if exe.is_file() else None


def _nm_symbol(exe: Path) -> int | None:
    nm = shutil.which("nm")
    if nm is None:
        return None
    out = subprocess.run(  # noqa: S603 - fixed args, local nm
        [nm, str(exe)], capture_output=True, text=True, timeout=60.0
    ).stdout
    for line in out.splitlines():
        m = _NM_LINE.match(line.strip())
        if m is not None:
            return int(m.group(1), 16)
    return None


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
def test_m11_frida_symbol_address_matches_ghidra_and_symtab(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("Linux-native dynamic<->static gate: POSIX only (skip != pass)")
    ghidra = _ghidra()
    if ghidra is None:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    frida = FridaClient()
    if not frida.available:
        pytest.skip("frida Python module not installed — cross-check Gate not run (skip != pass)")
    exe = _build_fixed_address_exe(tmp_path)
    if exe is None:
        pytest.skip("cannot build a -no-pie -rdynamic executable — skip != pass")
    truth = _nm_symbol(exe)
    if truth is None:
        pytest.skip("nm unavailable or symbol not found — no ground truth (skip != pass)")

    # Static side: Ghidra recovers gate_reveal at a fixed address and decompiles
    # its exact arithmetic.
    project = tmp_path / "ghidra_project"
    funcs = ghidra.functions(exe, project, limit=256, timeout=_ANALYZE_TIMEOUT_S)
    assert funcs.get("mode") == "functions"
    entry_for = {str(i.get("name") or ""): str(i.get("entry")) for i in funcs["items"]}
    assert "gate_reveal" in entry_for, list(entry_for)
    assert "main" in entry_for, list(entry_for)
    ghidra_entry = int(entry_for["gate_reveal"], 16)

    decomp = ghidra.decompile(exe, project, entry_for["gate_reveal"], timeout=_ANALYZE_TIMEOUT_S)
    reveal_c = str(decomp.get("decompiled") or "")
    assert "0x41" in reveal_c, reveal_c
    assert "^" in reveal_c, reveal_c
    assert "+ 7" in reveal_c, reveal_c

    # Dynamic side: Frida resolves gate_reveal in the live process.
    host = subprocess.Popen(
        [str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        time.sleep(0.6)
        assert host.poll() is None, "fixture exited early"
        assert frida.attach(host.pid, allowed_pid=host.pid).get("attached") is True

        # The exe's own module is the main image; its exports include gate_reveal.
        exports = frida.exports(host.pid, exe.name, allowed_pid=host.pid, limit=256)
        assert exports.get("found") is True
        by_name = {str(e.get("name")): e for e in exports["exports"]}
        assert "gate_reveal" in by_name, list(by_name)
        frida_addr = int(by_name["gate_reveal"]["address"], 16)

        # The core claim: dynamic resolution, static recovery and the symbol
        # table all place gate_reveal at the very same address.
        assert frida_addr == truth, (hex(frida_addr), hex(truth))
        assert ghidra_entry == truth, (hex(ghidra_entry), hex(truth))
    finally:
        host.terminate()
        try:
            host.wait(timeout=5)
        except subprocess.TimeoutExpired:
            host.kill()
