"""radare2 analysis live gate: strings, imports and disasm on Linux.

The existing r2 live gate only lists functions (and on ``main`` it still needs a
Windows PE fixture, so it skips on Linux entirely). radare2 is cross-platform,
and the r2 line exposes far more than function listing -- ``r2.strings``,
``r2.imports`` and ``r2.disasm`` are all tools an operator uses, and none of
them ever ran against a real binary; their parsing only saw mocks. This gate
compiles a small ELF and drives ``R2Client`` across that surface, so the depth
matches the Ghidra gate rather than stopping at "some functions". (``r2.xrefs``
has its own dedicated live gate in ``test_r2_xrefs_to_address_live_gate.py``.)

Skip != pass: the gate skips with a reason when r2 or a C compiler is absent, and
runs for real when both are present. CI installs r2, so a skip there is a genuine
regression rather than a bare machine.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import R2Client

# A distinctive string literal and named helpers so the assertions prove r2
# recovered real facts (this exact string, these functions, the printf import)
# rather than merely returning non-empty lists. -O0 keeps the helpers from being
# inlined and -no-pie fixes addresses so disasm lands where aflj reported.
_MARKER = "r2_gate_marker"
_FIXTURE_SRC = f"""
#include <stdio.h>

int add_numbers(int a, int b) {{ return a + b; }}

int multiply(int a, int b) {{
    int result = 0;
    for (int i = 0; i < b; i++) result += a;
    return result;
}}

int main(int argc, char **argv) {{
    int summed = add_numbers(argc, 7);
    int scaled = multiply(summed, 3);
    printf("{_MARKER} %d\\n", scaled);
    return 0;
}}
"""


def _compile_elf(tmp_path: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = tmp_path / "r2_analysis_fixture.c"
    src.write_text(_FIXTURE_SRC, encoding="utf-8")
    out = tmp_path / "r2_analysis_fixture.elf"
    result = subprocess.run(
        [compiler, "-O0", "-no-pie", "-o", str(out), str(src)],
        capture_output=True,
        timeout=120,
    )
    return out if result.returncode == 0 and out.is_file() else None


def _function_offset(functions: dict[str, Any], needle: str) -> int | None:
    for item in functions.get("items", []):
        if needle not in str(item.get("name")):
            continue
        # Consume the backend's normalized ``address`` (its stable contract),
        # not radare2's raw field, whose name drifts across versions: ``aflj``
        # entries carry ``offset`` on older radare2 but ``addr`` on 6.2+, so a
        # bare ``item["offset"]`` silently resolves to None on modern builds.
        address = item.get("address")
        if isinstance(address, dict):
            for key in ("va", "rva"):
                value = address.get(key)
                if isinstance(value, int):
                    return value
        for key in ("offset", "addr"):
            value = item.get(key)
            if isinstance(value, int):
                return int(value)
    return None


@pytest.mark.integration
def test_r2_recovers_strings_imports_and_disasm(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — analysis Gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)
    if binary is None:
        pytest.skip("no C compiler to build the fixture — Gate not run (skip != pass)")

    functions = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert functions.get("parsed") is True
    names = {str(item.get("name")) for item in functions["items"]}
    # The named helpers must be recovered, not just "some" functions.
    assert any("add_numbers" in n for n in names)
    assert any("multiply" in n for n in names)
    assert any(n == "main" or n.endswith(".main") for n in names)

    strings = client.run(binary, ["izj"], timeout=60.0)
    assert _MARKER in strings.get("raw", "") or _MARKER in str(strings.get("items", []))

    imports = client.run(binary, ["iij"], timeout=60.0)
    # The ELF calls printf, so a real import table lists it.
    assert "printf" in imports.get("raw", "") or "printf" in str(imports.get("items", []))

    add_offset = _function_offset(functions, "add_numbers")
    assert add_offset is not None, "could not resolve add_numbers to disassemble"

    disasm = client.disasm(binary, add_offset, count=24, timeout=60.0)
    assert disasm.get("parsed") is True
    ops = disasm.get("items") or []
    assert ops, "disassembly returned no instructions"
    listing = " ".join(str(op.get("disasm") or op.get("opcode") or "") for op in ops)
    # A real disassembly of add_numbers contains its addition and its return.
    assert "add" in listing
    assert "ret" in listing
