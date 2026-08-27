"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

The PE test needs a Windows fixture built by ``fixtures/native/build.ps1`` and
so only runs where that fixture exists. The ELF test compiles a tiny native
binary on the fly, so it is the portable half that actually exercises the r2
backend on Linux (or anywhere a C compiler and r2 are both present) instead of
skipping for a missing ``.exe``. Both skip honestly, and skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# A handful of named functions with a call edge, so ``aflj`` has something to
# find and ``pdj`` has real instructions to disassemble. Harmless: it xors a
# byte and adds a constant, the same shape as the checked-in crackme fixture.
_ELF_SOURCE = """
#include <stdio.h>
static int mangle(int x) { return (x ^ 0x41) + 7; }
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; i < 8; i++) acc += mangle(s[i]);
    return acc;
}
int main(int argc, char **argv) {
    if (argc > 1) return crackme_check(argv[1]);
    printf("gate\\n");
    return 0;
}
"""


def _build_native_fixture(tmp_path: Path) -> Path | None:
    """Compile a tiny native binary, or None when no compiler is available."""
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "r2_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    binary = tmp_path / "r2_fixture.bin"
    # -no-pie keeps the addresses stable and function starts easy to reason
    # about; fall back to a plain build if the toolchain rejects the flags.
    for extra in (["-O0", "-fno-pic", "-no-pie"], ["-O0"], []):
        try:
            subprocess.run(
                [compiler, *extra, str(source), "-o", str(binary)],
                check=True,
                capture_output=True,
                timeout=60.0,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue
        if binary.is_file():
            return binary
    return None


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        assert item["address"].get("module") == fixture.name


@pytest.mark.integration
def test_m11_r2_live_elf_functions_and_disasm(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _build_native_fixture(tmp_path)
    if fixture is None:
        pytest.skip("no C compiler (cc/gcc/clang) — ELF Gate not run (skip≠pass)")

    # open() is one-shot validation and must confirm r2 can read the binary.
    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True
    assert opened.get("info")

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("module") == fixture.name
    # entry0, main, and our two functions at least; analysis always finds more.
    assert funcs.get("count", 0) >= 3

    names = {str(item.get("name") or "") for item in funcs["items"]}
    # r2 prefixes symbols (``sym.crackme_check``), so match on the substring.
    assert any(name.endswith("main") or name == "main" for name in names), names
    assert any("crackme_check" in name for name in names), names

    # Every function carries a unified Address with at least a VA. ELF here has
    # no PE ImageBase, so the RVA/module fields are legitimately absent.
    target = None
    for item in funcs["items"]:
        address = item.get("address")
        assert isinstance(address, dict)
        assert isinstance(address.get("va"), int)
        if "crackme_check" in str(item.get("name") or ""):
            target = int(address["va"])
    assert target is not None

    # Disassembly at a real function start returns mapped instructions, not a
    # bare blob: this is the pdj whitelist + JSON parse + address enrichment.
    disasm = client.disasm(fixture, target, count=4, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("address_va") == target
    assert isinstance(disasm.get("items"), list)
    assert disasm["items"], disasm
