"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Small, unstripped C program: r2 must recover at least one named function from
# it. Kept trivial so `aa` finds functions on any target architecture cc emits.
_ELF_SOURCE = """
int headless_compute(int a, int b) { return a * b + 7; }
int main(void) { return headless_compute(3, 4); }
"""


def _portable_target(tmp_path: Path) -> Path | None:
    """The Windows PE fixture when built, otherwise a tiny ELF compiled here.

    r2 is cross-platform and its address mapping is exercised the same way on an
    ELF as on a PE, so this gate should not sit skipped on Linux for want of a
    Windows-only fixture that only ``build.ps1`` produces. Prefer the PE fixture
    when present (Windows/CI), else compile a small unstripped ELF when a C
    compiler is available. Skip -- not fail -- when neither exists, so a bare
    machine stays honest (skip != pass).
    """
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if fixture.is_file():
        return fixture
    if os.name == "nt":
        return None
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        return None
    source = tmp_path / "r2_fixture.c"
    source.write_text(_ELF_SOURCE, encoding="utf-8")
    out = tmp_path / "r2_fixture"
    try:
        subprocess.run(
            [compiler, "-O0", "-o", str(out), str(source)],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out if out.is_file() else None


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _portable_target(tmp_path)
    if fixture is None:
        pytest.skip("no r2 target: build the PE fixture or install a C compiler (skip≠pass)")

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
