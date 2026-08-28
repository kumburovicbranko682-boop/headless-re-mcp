"""r2 disasm live gate: pdj must disassemble *at* the requested address.

The r2 live gate exercised functions (``aflj``) but never ``disasm``, so the one
r2 method that takes an address and shells out had no real-tool coverage of the
property that actually matters: that ``pdj N @ <addr>`` seeks to ``<addr>`` and
returns the instructions there. That is not hypothetical -- the sibling
``xrefs`` method shipped building ``axj @ <addr>``, which modern r2 answers by
dumping the whole cross-reference database regardless of the seek, so an
address-scoped call silently returned global results. This gate pins disasm's
address scoping against the real tool: disassemble at two distinct function
entries and assert each reply begins exactly at the address asked for. skip !=
pass -- it skips honestly when r2 or a C compiler is absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_SOURCE = """
int addtwo(int a, int b){ return a + b; }
int mulmix(int a, int b){ return a * b + addtwo(a, b); }
int main(void){ return mulmix(3, 4); }
"""


def _first_va(item: dict) -> int | None:
    address = item.get("address")
    if isinstance(address, dict) and isinstance(address.get("va"), int):
        return address["va"]
    return None


@pytest.mark.integration
def test_r2_disasm_scopes_to_the_requested_address(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — r2 disasm Gate not run (skip != pass)")
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("no C compiler — r2 disasm Gate not run (skip != pass)")
    source = tmp_path / "fx.c"
    source.write_text(_SOURCE, encoding="utf-8")
    binary = tmp_path / "fx"
    build = subprocess.run(
        [compiler, "-O0", "-no-pie", "-o", str(binary), str(source)],
        capture_output=True,
    )
    if build.returncode != 0 or not binary.is_file():
        pytest.skip(
            "could not build the ELF fixture — r2 disasm Gate not run (skip != pass): "
            f"{build.stderr.decode('utf-8', 'replace')[:200]}"
        )

    funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True, funcs
    # Two distinct function entries with concrete virtual addresses. r2 names the
    # compiled functions sym.addtwo / sym.mulmix; fall back to any two with a va.
    entries = {
        str(item.get("name")): va
        for item in funcs.get("items", [])
        if (va := _first_va(item)) is not None
    }
    named = [entries[name] for name in ("sym.addtwo", "sym.mulmix") if name in entries]
    targets = named if len(named) >= 2 else sorted(set(entries.values()))[:2]
    if len(targets) < 2:
        pytest.skip("r2 found fewer than two addressable functions — skip != pass")

    seen_first: list[int] = []
    for address in targets:
        out = client.disasm(binary, address, count=4, timeout=60.0)
        assert out.get("parsed") is True, out
        assert out.get("count", 0) >= 1, out
        first = out["items"][0]
        first_va = _first_va(first)
        began = f"{first_va:#x}" if first_va is not None else repr(first_va)
        assert first_va == address, (
            f"disasm at {address:#x} began at {began}; pdj did not honor the @ seek"
        )
        seen_first.append(first_va)

    # Distinct addresses must yield distinct starting instructions: proof the
    # address is a real parameter, not ignored the way axj ignored it.
    assert len(set(seen_first)) == len(seen_first), seen_first
