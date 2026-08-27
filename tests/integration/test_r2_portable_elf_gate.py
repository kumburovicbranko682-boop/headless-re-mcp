"""Portable r2 live gate: real radare2 analysis of a Linux ELF.

The other r2 gate (test_m11_r2_live_gate.py) only runs against a prebuilt
Windows PE fixture, so on Linux the portable static-analysis backend had no
*live* coverage at all -- every r2 unit test mocks ``run_bounded``. radare2 is
format-agnostic, so this gate compiles a tiny ELF with the system C compiler
and drives the real binary end to end: open, analyse, list functions, and
confirm the address mapping degrades to a plain ``va`` when there is no PE
image base to compute an ``rva`` from.

skip != pass: it skips only when radare2 or a C compiler is genuinely absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_C_SOURCE = """
#include <stdio.h>

int add(int a, int b) { return a + b; }

int square(int n) { return n * n; }

int main(void) {
    printf("%d\\n", add(square(3), 4));
    return 0;
}
"""


def _c_compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _compile_elf(tmp_path: Path) -> Path:
    compiler = _c_compiler()
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build an ELF fixture (skip != pass)")
    source = tmp_path / "sample.c"
    source.write_text(_C_SOURCE, encoding="utf-8")
    binary = tmp_path / "sample.elf"
    # -O0 keeps add/square from being inlined into main so aflj sees them; not
    # stripped, so both the symbol table and analysis agree they exist.
    result = subprocess.run(
        [compiler, "-O0", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or not binary.is_file():
        pytest.skip(f"C compiler could not build the ELF fixture: {result.stderr[:400]}")
    return binary


@pytest.mark.integration
def test_r2_portable_elf_open_and_functions(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    opened = client.open(binary, timeout=60.0)
    assert opened.get("opened") is True
    # ``i`` reports the file class; an ELF must not be mistaken for a PE.
    assert "elf" in opened.get("info", "").lower()

    funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1

    # An ELF has no PE ImageBase, so mapping cannot synthesise an rva/module and
    # must fall back to a bare virtual address. This is the portable-format path
    # the PE gate never exercises.
    assert "image_base" not in funcs
    item = funcs["items"][0]
    address = item.get("address")
    assert isinstance(address, dict)
    assert "va" in address
    assert "rva" not in address
    assert "module" not in address


@pytest.mark.integration
def test_r2_portable_elf_disasm_and_xrefs(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("count", 0) >= 1
    entry = funcs["items"][0]
    va = entry["address"]["va"]

    disasm = client.disasm(binary, va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count") == 8
    assert disasm.get("address_va") == va

    xrefs = client.xrefs(binary, va, timeout=60.0)
    # xrefs may legitimately be empty for an entry function; the contract is a
    # structured, parsed envelope, not a crash.
    assert xrefs.get("parsed") is True
    assert isinstance(xrefs.get("items"), list)
