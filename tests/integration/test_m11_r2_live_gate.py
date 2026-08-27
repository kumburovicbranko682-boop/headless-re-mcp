"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

radare2 is a *portable* backend, so this gate must be able to run away from
Windows. It prefers the shared PE fixture when it is present (the same binary the
IDA/x64dbg gates use, which exercises PE image-base → rva mapping), and otherwise
falls back to a tiny ELF compiled on the spot so the backend still gets live
coverage on Linux/macOS instead of skipping for want of a Windows artifact.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Two named functions so `aflj` has something to map even before symbols are
# stripped; -O0 keeps `helper` from being inlined into `main`.
_ELF_FIXTURE_SOURCE = """
int helper(int value) { return value * 3 + 1; }
int main(void) { return helper(7) & 0x7f; }
"""


def _compile_elf_fixture(destination: Path) -> Path | None:
    """Build a small native ELF/Mach-O with whichever C compiler is on PATH."""
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    source = destination.with_suffix(".c")
    source.write_text(_ELF_FIXTURE_SOURCE, encoding="utf-8")
    try:
        subprocess.run(
            [compiler, "-O0", "-o", str(destination), str(source)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return destination if destination.is_file() else None


def _resolve_fixture(tmp_path: Path) -> Path | None:
    pe_fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if pe_fixture.is_file():
        return pe_fixture
    return _compile_elf_fixture(tmp_path / "r2_native_fixture")


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _resolve_fixture(tmp_path)
    if fixture is None:
        pytest.skip("no PE fixture and no C compiler to build a native one (skip≠pass)")

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    # rva mapping only applies to formats with a preferred image base (PE); an
    # ELF fixture is va-only, and that is the honest result on this platform.
    if "rva" in item["address"]:
        assert item["address"].get("module") == fixture.name
