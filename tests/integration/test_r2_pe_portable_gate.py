"""radare2 PE-on-Linux portability gate: the r2 backend reads Windows PEs.

radare2 is the project's *portable* backend, yet the only PE it was ever pointed
at is a committed Windows fixture that is absent on Linux CI -- so ``test_m11_r2_
live_gate.py`` falls back to a locally compiled ELF there and the PE-specific
paths (format identification, ImageBase -> rva address mapping, the PE import
table) never actually run. This gate closes that hole with no Windows and no
committed artifact: it cross-compiles a real PE32+ with mingw-w64 and drives the
same read surface (``iI`` / ``aflj`` / ``iij`` / ``izj`` / ``pd``) against the
real r2 on PATH, proving the backend analyses Windows binaries on Linux.

The rva mapping is the crux -- an ELF has no preferred image base, so only a PE
exercises the ``module`` + ``rva`` fields the address enricher emits. Skips
honestly when r2/rizin or the mingw cross-compiler is absent (skip != pass).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "HEADLESS_RE_PE_R2_MARKER"
# GetCurrentProcessId pulls a kernel32 import in; printf pulls the CRT in; the
# marker gives izj something to find. -O0 keeps the helpers from being inlined.
_C_SOURCE = textwrap.dedent(
    f"""
    #include <windows.h>
    #include <stdio.h>
    static const char *MARKER = "{_MARKER}";
    __declspec(noinline) int pe_helper(int v) {{ return v * 3 + 1; }}
    __declspec(noinline) int pe_compute(int x) {{
        return pe_helper(x) + (int) GetCurrentProcessId();
    }}
    int main(void) {{
        printf("%s %d\\n", MARKER, pe_compute(7));
        return 0;
    }}
    """
)


def _compile_pe(dest_dir: Path) -> Path | None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    if compiler is None:
        return None
    src = dest_dir / "pefix.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    out = dest_dir / "pefix.exe"
    if subprocess.run(
        [compiler, "-O0", "-o", str(out), str(src)], capture_output=True
    ).returncode == 0 and out.is_file():
        return out
    return None


def _raw_text(result: dict) -> str:
    """r2 non-JSON commands return their text under raw/text; be tolerant."""
    for key in ("raw", "text", "output"):
        value = result.get(key)
        if isinstance(value, str) and value:
            return value
    return json.dumps(result)


def _basenames(names: list[str]) -> set[str]:
    return {str(name).split(".")[-1] for name in names if name}


@dataclass
class _Harness:
    client: R2Client
    pe: Path
    functions: dict
    entries: dict[str, int]


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> _Harness:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — r2 PE-portability Gate not run (skip != pass)")
    root = tmp_path_factory.mktemp("r2pe")
    pe = _compile_pe(root)
    if pe is None:
        pytest.skip(
            "mingw-w64 (x86_64-w64-mingw32-gcc) not installed — "
            "r2 PE-portability Gate not run (skip != pass)"
        )
    functions = client.run(pe, ["aa", "aflj"], timeout=60.0)
    entries: dict[str, int] = {}
    for item in functions.get("items", []):
        name = str(item.get("name") or "")
        va = item.get("offset")
        if isinstance(va, int) and name:
            entries[name.split(".")[-1]] = va
    return _Harness(client=client, pe=pe, functions=functions, entries=entries)


@pytest.mark.integration
def test_open_and_info_identify_a_windows_pe(_harness: _Harness) -> None:
    opened = _harness.client.open(_harness.pe, timeout=60.0)
    assert opened["opened"] is True
    info = _raw_text(_harness.client.run(_harness.pe, ["iI"], timeout=60.0))
    # r2 must recognise the Windows container, not treat it as raw bytes.
    assert "PE32+" in info, info
    assert "windows" in info.lower(), info


@pytest.mark.integration
def test_functions_carry_pe_image_base_rva_mapping(_harness: _Harness) -> None:
    functions = _harness.functions
    assert functions["parsed"] is True
    # A linked PE drags the whole CRT in, so this is comfortably many functions.
    assert functions["count"] >= 5, functions.get("count")
    mapped = [
        item
        for item in functions["items"]
        if isinstance(item.get("address"), dict) and "rva" in item["address"]
    ]
    # The ImageBase -> rva mapping is what an ELF can never produce; its presence
    # is the proof the backend read this as a PE and mapped through the base.
    assert mapped, "no function carried an rva -- PE image base mapping did not run"
    address = mapped[0]["address"]
    assert "va" in address, address
    assert address.get("module") == _harness.pe.name, address


@pytest.mark.integration
def test_imports_list_windows_api_symbols(_harness: _Harness) -> None:
    result = _harness.client.run(_harness.pe, ["iij"], timeout=60.0)
    assert result["parsed"] is True
    assert result["count"] >= 1
    names = _basenames([str(item.get("name") or "") for item in result.get("items", [])])
    # pe_compute calls GetCurrentProcessId, so the kernel32 import must be listed.
    assert "GetCurrentProcessId" in names, sorted(names)


@pytest.mark.integration
def test_strings_find_the_embedded_marker(_harness: _Harness) -> None:
    result = _harness.client.run(_harness.pe, ["izj"], timeout=60.0)
    assert result["parsed"] is True
    strings = [str(item.get("string", "")) for item in result.get("items", [])]
    assert any(_MARKER in value for value in strings), strings


@pytest.mark.integration
def test_disasm_decodes_pe_code(_harness: _Harness) -> None:
    # entry0 always exists in a linked PE; fall back to any mapped function.
    va = _harness.entries.get("entry0")
    if va is None and _harness.entries:
        va = next(iter(_harness.entries.values()))
    assert va is not None, f"no function VA found among {sorted(_harness.entries)}"
    result = _harness.client.disasm(_harness.pe, va, count=8, timeout=60.0)
    assert result["parsed"] is True
    assert result["count"] >= 1
    opcodes = [str(item.get("opcode") or item.get("disasm") or "") for item in result["items"]]
    assert any(opcodes), opcodes
    assert result.get("address_va") == va
