"""radare2 static live gate: functions/strings/imports/disasm/xrefs on an ELF.

The existing r2 gate (``test_m11_r2_live_gate.py``) only opens the Windows PE
fixture and checks one function's address mapping, so on Linux it skips for want
of that fixture and the r2 backend's parsing paths (``aflj`` / ``izj`` / ``iij``
/ ``pdj`` / ``axj`` through ``enrich_r2_payload``) never ran live here. This
compiles a tiny ELF on the fly -- no committed fixture, no Windows -- and
exercises the whole read surface end to end against the real r2 on PATH.

It skips honestly when r2/rizin or a C compiler is absent -- skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "HEADLESS_RE_R2_MARKER"
_C_SOURCE = textwrap.dedent(
    f"""
    #include <stdio.h>
    const char *marker(void) {{ return "{_MARKER}"; }}
    int add(int a, int b) {{ return a + b; }}
    int compute(int x) {{ return add(x, 42); }}
    int main(void) {{
        printf("%s %d\\n", marker(), compute(1));
        return 0;
    }}
    """
)


def _compile_elf(dest_dir: Path) -> Path | None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        return None
    src = dest_dir / "r2fix.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    out = dest_dir / "r2fix.elf"
    # -no-pie keeps a fixed load address so function VAs are stable; fall back to
    # a plain build if the toolchain rejects those flags.
    for args in (
        [compiler, "-O0", "-fno-pie", "-no-pie", "-o", str(out), str(src)],
        [compiler, "-O0", "-o", str(out), str(src)],
    ):
        if subprocess.run(args, capture_output=True).returncode == 0 and out.is_file():
            return out
    return None


def _basenames(names: list[str]) -> set[str]:
    """r2 labels functions sym.add / main; compare on the last dotted component."""
    return {str(name).split(".")[-1] for name in names if name}


@dataclass
class _Harness:
    client: R2Client
    elf: Path
    functions: dict
    entries: dict[str, int]


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> _Harness:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — r2 Static Gate not run (skip != pass)")
    root = tmp_path_factory.mktemp("r2static")
    elf = _compile_elf(root)
    if elf is None:
        pytest.skip(
            "no C compiler to build the ELF fixture — r2 Static Gate not run (skip != pass)"
        )
    functions = client.run(elf, ["aa", "aflj"], timeout=60.0)
    # Map basename -> VA for the disasm/xrefs lookups the other tests reuse.
    entries: dict[str, int] = {}
    for item in functions.get("items", []):
        name = str(item.get("name") or "")
        va = item.get("offset")
        if isinstance(va, int) and name:
            entries[name.split(".")[-1]] = va
    return _Harness(client=client, elf=elf, functions=functions, entries=entries)


@pytest.mark.integration
def test_open_validates_the_binary(_harness: _Harness) -> None:
    opened = _harness.client.open(_harness.elf, timeout=60.0)
    assert opened["opened"] is True
    assert isinstance(opened["info"], str)
    assert opened["info"]


@pytest.mark.integration
def test_functions_lists_the_named_functions(_harness: _Harness) -> None:
    functions = _harness.functions
    assert functions["parsed"] is True
    assert functions["count"] >= 1
    names = [item.get("name") for item in functions["items"]]
    assert {"add", "compute", "main", "marker"} <= _basenames(names), names
    # ELF has no PE ImageBase, so addresses carry a virtual address, not rva.
    first = functions["items"][0]
    assert isinstance(first.get("address"), dict)
    assert "va" in first["address"]


@pytest.mark.integration
def test_strings_finds_the_embedded_marker(_harness: _Harness) -> None:
    result = _harness.client.run(_harness.elf, ["izj"], timeout=60.0)
    assert result["parsed"] is True
    strings = [str(item.get("string", "")) for item in result.get("items", [])]
    assert any(_MARKER in value for value in strings), strings


@pytest.mark.integration
def test_imports_lists_libc_symbols(_harness: _Harness) -> None:
    result = _harness.client.run(_harness.elf, ["iij"], timeout=60.0)
    assert result["parsed"] is True
    assert result["count"] >= 1
    names = _basenames([str(item.get("name") or "") for item in result.get("items", [])])
    # printf is called from main, so the dynamic import must be listed.
    assert "printf" in names, names


@pytest.mark.integration
def test_disasm_returns_instructions_for_compute(_harness: _Harness) -> None:
    compute_va = _harness.entries.get("compute")
    assert compute_va is not None, f"compute not found among {sorted(_harness.entries)}"
    result = _harness.client.disasm(_harness.elf, compute_va, count=8, timeout=60.0)
    assert result["parsed"] is True
    assert result["count"] >= 1
    opcodes = [str(item.get("opcode") or item.get("disasm") or "") for item in result["items"]]
    assert any(opcodes), opcodes
    # The requested address is echoed back as a mapped Address.
    assert result.get("address_va") == compute_va


@pytest.mark.integration
def test_xrefs_parse_for_a_function_address(_harness: _Harness) -> None:
    add_va = _harness.entries.get("add")
    assert add_va is not None, f"add not found among {sorted(_harness.entries)}"
    result = _harness.client.xrefs(_harness.elf, add_va, timeout=60.0)
    assert result["parsed"] is True
    # r2 returns cross-reference rows; each carries a mapped from/to address.
    for item in result.get("items", []):
        assert "address" in item or "from_address" in item
