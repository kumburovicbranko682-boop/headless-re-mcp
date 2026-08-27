"""M11 r2 cross-format gate: PE import table and RVA/ImageBase mapping.

r2 is the cross-platform static backend, but every live r2 gate that runs on
Linux uses an ELF -- the PE half of the live gate needs a checked-in Windows
``.exe`` and otherwise skips, so on a normal Linux CI run r2's PE front end is
never exercised. That front end is materially different from ELF: a PE resolves
calls through an import table keyed by DLL, and its addresses are RVAs relative
to an ImageBase rather than absolute VAs. The ELF gate even notes the RVA/module
address fields are "legitimately absent" there, so nothing proves r2 populates
them.

This gate cross-compiles a PE with mingw-w64 (no Windows, no checked-in binary),
confirms it is a PE from the MZ/PE headers, and asserts r2 detects the pe64
format, recovers the import table (``Sleep`` from KERNEL32, ``puts`` from
msvcrt) with per-import DLL names and mapped addresses, and recovers functions
carrying module-relative RVAs. The decisive structural check ties them together:
for both an import and a recovered function, ``va - rva`` equals the same
positive ImageBase, proving r2 computed the PE address model, not just parsed
symbols. skip != pass when radare2/rizin or the mingw cross compiler is missing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

# Sleep (kernel32) and puts (msvcrt) give two imports from two distinct DLLs;
# crackme_check is a named function to anchor the RVA checks.
_SRC = r"""
#include <stdio.h>
#include <windows.h>

__attribute__((noinline))
int crackme_check(const char *s) {
    int acc = 0;
    for (int i = 0; s[i]; i++) acc += (s[i] ^ 0x41) + 7;
    return acc;
}

int main(int argc, char **argv) {
    Sleep(1);
    if (argc > 1) return crackme_check(argv[1]);
    puts("pe-gate");
    return 0;
}
"""
_MINGW = "x86_64-w64-mingw32-gcc"


def _build_pe(dest: Path) -> Path | None:
    compiler = shutil.which(_MINGW)
    if compiler is None:
        return None
    src = dest / "fixture.c"
    src.write_text(_SRC, encoding="utf-8")
    exe = dest / "fixture.exe"
    try:
        subprocess.run(  # noqa: S603 - fixed args, local cross compiler
            [compiler, "-O0", str(src), "-o", str(exe)],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return exe if exe.is_file() else None


def _is_pe(binary: Path) -> bool:
    """True when the file has the MZ stub and a PE\\0\\0 signature it points to."""
    blob = binary.read_bytes()
    if blob[:2] != b"MZ" or len(blob) < 0x40:
        return False
    pe_off = int.from_bytes(blob[0x3C:0x40], "little")
    return blob[pe_off : pe_off + 4] == b"PE\x00\x00"


def _addr_of(entry: dict[str, object]) -> dict[str, object] | None:
    addr = entry.get("address")
    return addr if isinstance(addr, dict) else None


@pytest.mark.integration
def test_m11_r2_reads_pe_imports_and_rva_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — PE Gate not run (skip != pass)")
    exe = _build_pe(tmp_path)
    if exe is None:
        pytest.skip(f"{_MINGW} missing — cannot build the PE fixture (skip != pass)")

    # Independent of r2: the fixture really is a PE.
    assert _is_pe(exe), exe.read_bytes()[:2]

    # open(): r2 identifies the Windows PE64 container.
    opened = client.open(exe, timeout=60.0)
    assert opened.get("opened") is True
    info = str(opened.get("info", "")).lower()
    assert "pe" in info, info[:400]
    assert "windows" in info, info[:400]

    # iij: the import table resolves both calls to their source DLLs, each with
    # a mapped address that carries an RVA, a VA and the module.
    imports = client.run(exe, ["iij"], timeout=60.0)
    assert imports.get("parsed") is True
    by_name = {str(i.get("name")): i for i in imports["items"]}
    assert "Sleep" in by_name and "puts" in by_name, sorted(by_name)
    assert by_name["Sleep"].get("libname", "").lower() == "kernel32.dll", by_name["Sleep"]
    assert by_name["puts"].get("libname", "").lower() == "msvcrt.dll", by_name["puts"]

    import_addr = _addr_of(by_name["Sleep"])
    assert import_addr is not None, by_name["Sleep"]
    assert import_addr.get("module") == exe.name, import_addr
    import_rva, import_va = import_addr.get("rva"), import_addr.get("va")
    assert isinstance(import_rva, int) and isinstance(import_va, int), import_addr

    # aflj: functions are recovered with module-relative RVAs (the branch the
    # ELF gate cannot reach, where RVA/module are absent).
    funcs = client.run(exe, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("module") == exe.name
    check = next((f for f in funcs["items"] if "crackme_check" in str(f.get("name"))), None)
    assert check is not None, [f.get("name") for f in funcs["items"]][:20]
    assert any(str(f.get("name")).endswith("main") for f in funcs["items"])
    func_addr = _addr_of(check)
    assert func_addr is not None, check
    assert func_addr.get("module") == exe.name, func_addr
    func_rva, func_va = func_addr.get("rva"), func_addr.get("va")
    assert isinstance(func_rva, int) and isinstance(func_va, int), func_addr

    # The decisive PE check: VA = ImageBase + RVA, the same positive ImageBase
    # for an import (in the IAT) and a function (in .text). This proves r2
    # computed the PE address model rather than merely echoing symbols.
    image_base_from_import = import_va - import_rva
    image_base_from_func = func_va - func_rva
    assert image_base_from_import == image_base_from_func, (
        image_base_from_import,
        image_base_from_func,
    )
    assert image_base_from_import > 0, image_base_from_import

    # Disassembly at the recovered function start returns mapped instructions.
    disasm = client.disasm(exe, func_va, count=4, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("items"), disasm
