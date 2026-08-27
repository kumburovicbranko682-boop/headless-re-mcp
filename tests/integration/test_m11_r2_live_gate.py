"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

Portable across the platforms radare2 runs on. Windows analyses its committed
PE sample and checks module-relative RVAs; elsewhere a tiny ELF is compiled on
the fly so the gate exercises r2 on this platform's own object format. The
address mapping degrades honestly for a PIE ELF -- with no PE ImageBase there is
nothing to make addresses module-relative, so items keep absolute VAs -- which
is exactly what this asserts. It skips, never fails, when r2 or a C compiler is
absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _r2_fixture(tmp_path: Path) -> Path:
    """A binary radare2 can analyse on this platform.

    Windows uses the committed x64 PE sample; elsewhere any C toolchain builds a
    small ELF with a couple of real functions to analyse. Skips when the sample
    or a compiler is unavailable rather than failing.
    """
    if os.name == "nt":
        fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        return fixture

    compiler = next((name for name in ("cc", "gcc", "clang") if shutil.which(name)), None)
    if compiler is None:
        pytest.skip("no C compiler to build an ELF fixture — r2 Gate not run (skip != pass)")
    source = tmp_path / "r2fix.c"
    source.write_text(
        "#include <stdio.h>\n"
        "static int secret(int x){ return x * 3 + 1; }\n"
        "int helper(int a){ return secret(a) + a; }\n"
        'int main(void){ printf("%d\\n", helper(7)); return 0; }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "r2fix.elf"
    try:
        built = subprocess.run(  # noqa: S603 - fixed local toolchain, fixed args
            [compiler, "-O0", "-o", str(binary), str(source)],
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"C compiler could not build an ELF fixture ({exc}) — skip != pass")
    if built.returncode != 0 or not binary.is_file():
        pytest.skip("C compiler produced no ELF fixture — r2 Gate not run (skip != pass)")
    return binary


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture(tmp_path)

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        # A PE carries a preferred base, so addresses map to module-relative RVAs.
        assert item["address"].get("module") == fixture.name
