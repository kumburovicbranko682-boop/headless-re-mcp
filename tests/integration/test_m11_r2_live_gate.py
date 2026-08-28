"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

radare2 is a portable backend the project supports on Linux, but the only
committed live target is a Windows PE built on Windows, so this gate used to
skip on Linux even with r2 installed -- a portable line that could never be
verified on the platform it is meant to run on. The gate now prefers the
Windows PE fixture when present (still asserting the PE rva/module mapping on a
configured Windows host) and otherwise builds a tiny ELF so the same
address-mapping path is exercised on POSIX. No compiler means an honest skip,
not a false pass.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# A minimal, standard-C program with a non-trivial function radare2 will pick up
# under `aa`. Kept portable (no __declspec/__cdecl) so cc/gcc/clang can build it.
_ELF_SOURCE = """\
#include <stdio.h>
int compute(int a, int b) { return a * b + 7; }
int main(void) { printf("%d\\n", compute(3, 5)); return 0; }
"""


def _windows_pe_fixture() -> Path | None:
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    return fixture if fixture.is_file() else None


def _build_elf_fixture() -> Path | None:
    """Compile and cache a tiny ELF so the portable r2 backend runs on POSIX."""
    out_dir = _PROJECT_ROOT / "artifacts" / "fixtures-linux"
    elf = out_dir / "r2_gate_fixture.elf"
    if elf.is_file():
        return elf
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    source = out_dir / "r2_gate_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    try:
        subprocess.run(
            [compiler, "-O0", "-o", str(elf), str(source)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return elf if elf.is_file() else None


def _gate_fixture() -> Path | None:
    """Prefer the Windows PE fixture; fall back to a built ELF on POSIX."""
    return _windows_pe_fixture() or _build_elf_fixture()


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _gate_fixture()
    if fixture is None:
        pytest.skip("no r2 gate fixture: Windows PE absent and no C compiler for an ELF")

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
