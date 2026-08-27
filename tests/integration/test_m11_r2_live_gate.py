"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

Two live paths, one per binary format. The PE path proves the rva/module
mapping the mature Windows pipeline depends on and only runs where the PE
fixture was built. The ELF path proves the same client on the platform the
project now calls a first-class core -- radare2 is fully cross-platform, but
until this the r2 line had *no* live coverage on Linux/macOS because the only
fixture was a Windows PE, so a regression in the non-PE (va-only) mapping would
have sailed through every green run there. It compiles a tiny fixture with the
system C compiler so it needs no committed binary; skip != pass when neither r2
nor a compiler is present.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Distinct, non-inlined functions with a clear call graph so ``aflj`` finds
# more than one function and ``axj`` finds real cross-references. Kept portable
# (no OS headers) so it builds to an ELF on Linux and a Mach-O on macOS.
_ELF_FIXTURE_C = """
#include <stdio.h>

__attribute__((noinline)) int r2_gate_leaf(int x) { return (x ^ 0x5a) + 3; }

__attribute__((noinline)) int r2_gate_middle(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += r2_gate_leaf(i);
    return total;
}

__attribute__((noinline)) int r2_gate_root(int n) {
    return r2_gate_middle(n) + r2_gate_leaf(n);
}

int main(void) {
    volatile int result = r2_gate_root(11);
    printf("r2-gate %d\\n", result);
    return 0;
}
"""


def _build_elf_fixture(tmp_path: Path) -> Path:
    """Compile the portable fixture, or skip when no C compiler is available."""
    compiler = next(
        (shutil.which(name) for name in ("cc", "gcc", "clang") if shutil.which(name)),
        None,
    )
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build an r2 ELF fixture (skip != pass)")
    source = tmp_path / "r2_gate_fixture.c"
    source.write_text(_ELF_FIXTURE_C, encoding="utf-8")
    out = tmp_path / "r2_gate_fixture"
    # -O0 keeps the helpers as separate functions; -no-pie fixes the load base
    # so the reported va is stable, with a fallback for toolchains that reject
    # it (some clang targets). Neither is required for the mapping under test.
    for extra in (["-no-pie"], []):
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [compiler, "-O0", *extra, "-o", str(out), str(source)],
            capture_output=True,
            text=True,
            timeout=120.0,
        )
        if completed.returncode == 0 and out.is_file():
            return out
    pytest.skip(
        f"C compiler present but could not build the r2 ELF fixture (skip != pass): "
        f"{completed.stderr.strip()[:400]}"
    )


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
def test_m11_r2_live_elf_maps_functions_disasm_and_xrefs(tmp_path: Path) -> None:
    """The portable path: same client, ELF binary, va-only mapping.

    A PE carries a preferred ImageBase, so its addresses map to rva+module. An
    ELF does not go through that header read, so ``address`` must be a bare va
    with no rva/module invented for it. Exercising functions, disasm and xrefs
    covers every ``enrich_r2_payload`` branch a caller hits on a non-PE target.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    fixture = _build_elf_fixture(tmp_path)

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    first = funcs["items"][0]
    assert isinstance(first.get("address"), dict)
    va = first["address"].get("va")
    assert isinstance(va, int) and va > 0
    # ELF has no PE ImageBase, so the mapping must not fabricate rva/module.
    assert "rva" not in first["address"]
    assert "module" not in first["address"]

    disasm = client.disasm(fixture, va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("items")
    assert disasm.get("address", {}).get("va") == va
    assert disasm.get("address_va") == va

    xrefs = client.xrefs(fixture, va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert xrefs.get("address", {}).get("va") == va
