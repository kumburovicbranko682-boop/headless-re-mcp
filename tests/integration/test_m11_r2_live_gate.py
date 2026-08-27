"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

radare2/rizin is a portable, non-Windows backend, so this gate must be able to
run its real analysis on Linux too. The prebuilt Windows PE fixture only exists
on a machine that ran the PowerShell fixture build, so on a Linux host with r2
installed the gate used to skip for want of a `.exe` it could never produce --
"skip != pass" that could never become pass. When the PE fixture is absent this
compiles a small portable ELF (a couple of named functions) so r2 analyses a
real binary here. It still skips honestly when neither a PE fixture nor a C
compiler is available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Two named functions plus main, so r2's `aflj` reports more than the runtime
# stubs. Deliberately portable C -- no __declspec/__cdecl, unlike the PE
# fixtures -- so a stock cc/gcc/clang builds it anywhere.
_PORTABLE_FIXTURE_SRC = """\
#include <stdio.h>
#include <string.h>

static int accumulate(const char *text) {
    int total = 0;
    for (size_t i = 0; text[i]; i++) total += (unsigned char)text[i];
    return total;
}

int transform(int seed) {
    return (int)((unsigned)seed * 2654435761u) ^ 0x5a5a5a5a;
}

int main(int argc, char **argv) {
    int acc = accumulate(argc > 1 ? argv[1] : "headless");
    printf("%d\\n", transform(acc) + argc);
    return 0;
}
"""


def _compile_portable_elf(tmp_path: Path) -> Path | None:
    """Build a tiny native binary with any available C compiler, or None."""
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "r2_portable_fixture.c"
    source.write_text(_PORTABLE_FIXTURE_SRC, encoding="utf-8")
    output = tmp_path / "r2_portable_fixture"
    # -no-pie gives absolute VAs (nicer for the address assertions); fall back to
    # a plain build when a toolchain rejects it (some clang/musl setups do).
    for args in (
        [compiler, "-O0", "-fno-pie", "-no-pie", "-o", str(output), str(source)],
        [compiler, "-O0", "-o", str(output), str(source)],
    ):
        try:
            subprocess.run(args, check=True, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        if output.is_file():
            return output
    return None


def _resolve_r2_fixture(tmp_path: Path) -> Path | None:
    """Prefer the prebuilt PE fixture; otherwise a freshly compiled ELF."""
    pe_fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if pe_fixture.is_file():
        return pe_fixture
    if os.name == "nt":
        # Windows owns the PE fixture through its build; don't assume a compiler.
        return None
    return _compile_portable_elf(tmp_path)


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _resolve_r2_fixture(tmp_path)
    if fixture is None:
        pytest.skip(
            "no PE fixture and no C compiler to build a portable one — "
            "live Gate not run (skip≠pass)"
        )

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        # A PE keeps ImageBase-relative RVAs tagged with the module; an ELF maps
        # to an absolute VA with no RVA, which the branch above already accepts.
        assert item["address"].get("module") == fixture.name
