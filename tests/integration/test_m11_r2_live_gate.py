"""M11 r2 live gate: address-mapped functions. skip≠pass when r2 missing.

radare2/rizin is a portable backend, so this gate must actually exercise it on
the platform it runs on rather than only on Windows. It prefers the checked-in
PE fixture (where it can also prove the rva+module mapping) and otherwise
compiles a tiny ELF on the fly, which is what lets the Linux CI job prove the
r2 line instead of skipping past it. It skips only when r2 is genuinely absent
or nothing can produce a native binary to point it at.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_FIXTURE_SOURCE = """
#include <stdio.h>
static int helper(int x) { return x * 3 + 1; }
int compute(int a, int b) { return helper(a) + helper(b); }
int main(void) { printf("%d\\n", compute(2, 5)); return 0; }
"""


def _build_elf_fixture(tmp_path: Path) -> Path | None:
    """Compile a small native binary so r2 has real functions to find.

    Returns ``None`` when no C compiler is available, which is a genuine skip
    rather than a pass: without a binary the gate cannot say anything about r2.
    """
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = tmp_path / "r2_fixture.c"
    source.write_text(_FIXTURE_SOURCE, encoding="utf-8")
    binary = tmp_path / "r2_fixture"
    try:
        subprocess.run(
            [compiler, "-O0", "-o", str(binary), str(source)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return binary if binary.is_file() else None


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")

    pe_fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if pe_fixture.is_file():
        fixture: Path | None = pe_fixture
        expect_pe_mapping = True
    else:
        fixture = _build_elf_fixture(tmp_path)
        expect_pe_mapping = False
    if fixture is None:
        pytest.skip("no PE fixture and no C compiler to build one — Gate not run (skip≠pass)")

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if expect_pe_mapping:
        # The PE carries a preferred ImageBase, so the mapper resolves an rva and
        # attributes it to the module. An ELF has no such base here, so it only
        # gets a va -- asserting rva there would demand behaviour r2 cannot give.
        assert "rva" in item["address"]
        assert item["address"].get("module") == fixture.name
