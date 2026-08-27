"""Live radare2 gate on a self-built ELF: functions, strings, disassembly.

The existing r2 live gate (test_m11_r2_live_gate.py) needs a Windows PE fixture
(artifacts/fixtures-x64/headless_fixture.exe) that is not committed, so it skips
in every clean checkout even when r2 is installed -- the r2 backend has no live
gate that actually runs anywhere. This gate stands on its own: it compiles a
tiny ELF with the system C compiler, then drives R2Client end to end and asserts
r2 recovered the named functions with mapped addresses, the marker string, and a
real disassembly. Linux-portable and hermetic; skips honestly (skip != pass)
when r2 or a C compiler is absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "H3adl3ss marker string"
_SOURCE = f"""
#include <stdio.h>
int add_numbers(int a, int b) {{ return a + b; }}
int mul_numbers(int a, int b) {{ return a * b; }}
int main(void) {{
    printf("{_MARKER}\\n");
    return add_numbers(2, 3) + mul_numbers(4, 5);
}}
"""


def _compile_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        pytest.skip("no C compiler (gcc/cc) — r2 ELF Gate not run (skip != pass)")
    source = tmp_path / "fixture.c"
    source.write_text(_SOURCE)
    binary = tmp_path / "fixture"
    # -no-pie keeps main at a stable absolute VA and the symbols un-stripped, so
    # the assertions below read the same across runs.
    result = subprocess.run(
        [compiler, "-O0", "-no-pie", str(source), "-o", str(binary)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"compile failed: {result.stderr}"
    assert binary.is_file()
    return binary


def _core_names(items: list[dict]) -> set[str]:
    # r2 names user functions sym.<name>; main is bare. Reduce to the C name.
    return {str(it.get("name", "")).split(".")[-1] for it in items}


@pytest.mark.integration
def test_r2_recovers_functions_strings_and_disassembly_from_an_elf(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — r2 ELF Gate not run (skip != pass)")
    elf = _compile_elf(tmp_path)

    assert client.open(elf, timeout=60.0).get("opened") is True

    funcs = client.run(elf, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    items = funcs["items"]
    # The two hand-written functions and main must all be recovered, or analysis
    # did not really run -- a stub that returned an empty/echoed payload fails.
    assert {"add_numbers", "mul_numbers", "main"} <= _core_names(items)
    # Every function carries a mapped address; ELF resolves to a virtual address.
    address = items[0].get("address")
    assert isinstance(address, dict), address
    assert "va" in address or "rva" in address

    strings = client.run(elf, ["izj"], timeout=60.0)
    assert strings.get("parsed") is True
    recovered = " ".join(str(s.get("string", "")) for s in strings.get("items", []))
    assert _MARKER in recovered  # the literal survived into the string table

    main = next(it for it in items if str(it.get("name", "")).endswith("main"))
    main_va = (main.get("address") or {}).get("va") or main.get("offset")
    assert isinstance(main_va, int), main_va
    disasm = client.disasm(elf, main_va, count=16, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count", 0) >= 1
    ops = [str(op.get("disasm", "")) for op in disasm.get("items", [])]
    assert any(ops), "disassembly produced no instruction text"
    mnemonics = " ".join(ops)
    # Real x86-64 instruction text, not an empty or echoed listing.
    assert any(m in mnemonics for m in ("push", "mov", "call", "lea", "ret", "endbr64"))
