"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

radare2/rizin are cross-platform, so this runs for real on Linux too. When the
Windows PE fixture is absent (a bare checkout, or any non-Windows machine) the
gate compiles a small ELF instead of skipping, so "skip != pass" means r2 is
genuinely missing rather than that the Windows build has not run.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_FIXTURE_SRC = """
#include <stdio.h>

int add_numbers(int a, int b) { return a + b; }

int main(int argc, char **argv) {
    printf("%d\\n", add_numbers(argc, 7));
    return 0;
}
"""


def _compile_portable_elf(tmp_path: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = tmp_path / "r2_fixture.c"
    src.write_text(_FIXTURE_SRC, encoding="utf-8")
    out = tmp_path / "r2_fixture.elf"
    result = subprocess.run(
        [compiler, "-O0", "-no-pie", "-o", str(out), str(src)],
        capture_output=True,
        timeout=120,
    )
    return out if result.returncode == 0 and out.is_file() else None


def _resolve_fixture(tmp_path: Path) -> Path | None:
    """Prefer the prebuilt PE fixture; otherwise a freshly compiled ELF."""
    pe_fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if pe_fixture.is_file():
        return pe_fixture
    return _compile_portable_elf(tmp_path)


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _resolve_fixture(tmp_path)
    if fixture is None:
        pytest.skip("no PE fixture and no C compiler — live Gate not run (skip≠pass)")

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
