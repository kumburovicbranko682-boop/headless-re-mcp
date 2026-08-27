"""r2 live gate on a native ELF. skip != pass when r2 or a compiler is missing.

The sibling ``test_m11_r2_live_gate`` only runs against a Windows PE fixture, so
the radare2 backend's non-PE path -- opening an ELF, analysing functions, and
mapping addresses for a target with no PE ImageBase -- was never exercised on a
Linux CI box even though r2 itself is installed there. This gate compiles a tiny
ELF in a temp dir and drives the real backend end to end, asserting both that
analysis works and that the address enrichment degrades to va-only (no rva /
module / image_base) for a non-PE target, which is the contract that separates
the ELF path from the PE path.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error

_C_SOURCE = """
#include <stdio.h>

int add(int a, int b) { return a + b; }
int mul(int a, int b) { return a * b; }

int main(void) {
    printf("hello %d %d\\n", add(2, 3), mul(4, 5));
    return 0;
}
"""

# -no-pie keeps the sample a plain ET_EXEC so the assertions do not depend on a
# toolchain default; the fallback covers compilers that reject those flags.
_FLAG_SETS: tuple[list[str], ...] = (
    ["-O0", "-fno-pic", "-no-pie"],
    ["-O0"],
    [],
)


def _compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _compile_elf(compiler: str, source: Path, out: Path) -> bool:
    for flags in _FLAG_SETS:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [compiler, *flags, "-o", str(out), str(source)],
            capture_output=True,
        )
        if result.returncode == 0 and out.is_file():
            return True
    return False


@pytest.fixture
def elf_binary(tmp_path: Path) -> Path:
    compiler = _compiler()
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — cannot build the ELF sample (skip != pass)")
    source = tmp_path / "sample.c"
    source.write_text(_C_SOURCE, encoding="utf-8")
    binary = tmp_path / "sample.elf"
    if not _compile_elf(compiler, source, binary):
        pytest.skip("compiler could not produce an ELF here (skip != pass)")
    return binary


@pytest.mark.integration
def test_r2_opens_and_analyses_a_native_elf(elf_binary: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")

    opened = client.open(elf_binary, timeout=60.0)
    assert opened.get("opened") is True
    assert opened.get("binary") == str(elf_binary)
    assert opened.get("info")

    funcs = client.run(elf_binary, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    items = funcs.get("items") or []
    assert items, "aflj returned no functions"

    # Every mapped function must carry a virtual address, and because an ELF has
    # no PE ImageBase the enrichment must not invent an rva or a module for it.
    with_address = [item for item in items if isinstance(item.get("address"), dict)]
    assert with_address, "no function carried a mapped address"
    for item in with_address:
        address = item["address"]
        assert "va" in address
        assert "rva" not in address
        assert "module" not in address
    assert "image_base" not in funcs


@pytest.mark.integration
def test_r2_disassembles_a_function_in_a_native_elf(elf_binary: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")

    funcs = client.run(elf_binary, ["aa", "aflj"], timeout=60.0)
    addresses = [
        item["offset"]
        for item in (funcs.get("items") or [])
        if isinstance(item.get("offset"), int)
    ]
    assert addresses, "no function offset to disassemble"

    disasm = client.disasm(elf_binary, addresses[0], count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count") == 8
    request_address = disasm.get("address")
    assert isinstance(request_address, dict)
    assert request_address.get("va") == addresses[0]
    assert "rva" not in request_address


@pytest.mark.integration
def test_r2_rejects_a_command_outside_the_whitelist(elf_binary: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")

    # A shell-out command is refused before r2 ever launches, so the whitelist
    # is a real boundary rather than documentation.
    with pytest.raises(R2Error) as excinfo:
        client.run(elf_binary, ["!id"], timeout=60.0)
    assert excinfo.value.code == "invalid_params"
