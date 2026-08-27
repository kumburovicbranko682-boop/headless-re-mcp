"""radare2 live gate for a Linux ELF, so the portable r2 line is exercised here.

``test_m11_r2_live_gate`` opens ``headless_fixture.exe`` -- a Windows PE that is
only built on the Windows job -- so on Linux it can only ever skip, and the
R2Client had no live coverage on the platform where it is the *portable* static
backend. This gate compiles a tiny ELF with named functions and drives the same
one-shot r2 path, so ``r2.open`` / ``r2.run(aa, aflj)`` / ``r2.disasm`` are
proven against a real binary on Linux. skip != pass: it skips honestly when r2
or a C compiler is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

# -O0 keeps the three functions distinct and inlining-free so r2 reports each
# one; the names are asserted below to prove real analysis, not just that r2 ran.
_SOURCE = """\
#include <stdio.h>
static int helper_add(int a, int b) { return a + b; }
int helper_compute(int x) { return helper_add(x, 7) * 2; }
int main(void) { printf("%d\\n", helper_compute(3)); return 0; }
"""


def _compiler() -> str | None:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _build_elf(tmp_path: Path) -> Path:
    compiler = _compiler()
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) — r2 ELF Gate not run (skip != pass)")
    source = tmp_path / "r2fixture.c"
    source.write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "r2fixture"
    # Compiler path comes from shutil.which and the args are fixed literals.
    result = subprocess.run(
        [compiler, "-O0", "-o", str(out), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or not out.is_file():
        pytest.skip(
            f"C compiler could not link the fixture ({result.returncode}) — "
            "r2 ELF Gate not run (skip != pass)"
        )
    return out


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="Linux/POSIX ELF gate; Windows uses the PE r2 gate")
def test_r2_live_analyzes_a_linux_elf(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — r2 ELF Gate not run (skip != pass)")
    elf = _build_elf(tmp_path)

    opened = client.open(elf, timeout=60.0)
    assert opened.get("opened") is True
    assert isinstance(opened.get("info"), str)

    funcs = client.run(elf, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    items = funcs.get("items")
    assert isinstance(items, list) and funcs.get("count", 0) >= 1

    # A direct ELF open has no runtime module, so every function is a static VA.
    first = items[0]
    assert isinstance(first.get("address"), dict)
    assert "va" in first["address"]

    # r2 actually walked our code rather than only reading the ELF header: the
    # source's own function names have to appear in the listing.
    names = [str(item.get("name") or "") for item in items]
    assert any(name.endswith("main") for name in names), names
    assert any("helper_compute" in name for name in names), names

    # And the disassembler returns instructions at a real function address.
    target = next((item for item in items if str(item.get("name") or "").endswith("main")), first)
    disassembled = client.disasm(elf, int(target["address"]["va"]), count=8, timeout=60.0)
    assert disassembled.get("parsed") is True
    assert isinstance(disassembled.get("items"), list) and disassembled["items"]
