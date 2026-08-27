"""M11 r2 architecture gate: the static pipeline on a non-x86 target.

The existing r2 static and xref gates prove the pipeline on x86-64 ELFs, but r2
earns its place in this project precisely because it is architecture-neutral --
a claim no x86-only fixture can back up. This gate cross-compiles the same
crackme to AArch64 and drives strings, imports, function recovery, disassembly
and the outbound xref graph against it. Before trusting r2 it independently
confirms the fixture really is AArch64 by reading the ELF e_machine, then
asserts r2 disassembles genuine ARM64 (stp/bl/b.ne, x29/sp), which no x86-64
decode could ever emit. skip != pass when radare2/rizin or the aarch64 cross
compiler is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_SRC = r"""
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int check_password(const char *s) {
    if (strcmp(s, "r2-arm-gate-marker-9d2c") == 0) {
        puts("access granted");
        return 1;
    }
    puts("access denied");
    return 0;
}

int main(int argc, char **argv) {
    const char *pw = argc > 1 ? argv[1] : "nope";
    return check_password(pw) ? 0 : 2;
}
"""
_MARKER = "r2-arm-gate-marker-9d2c"
_EM_AARCH64 = 183  # ELF e_machine value for AArch64.


def _arm_compiler() -> str | None:
    return shutil.which("aarch64-linux-gnu-gcc")


def _build_aarch64_elf(dest: Path) -> Path:
    compiler = _arm_compiler()
    assert compiler is not None
    src = dest / "fixture.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "fixture.arm64"
    subprocess.run(  # noqa: S603 - fixed args, local cross compiler
        [compiler, "-O0", "-fno-inline", "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


def _elf_machine(binary: Path) -> tuple[int, int]:
    """Return (ei_class, e_machine) straight from the ELF header."""
    header = binary.read_bytes()[:20]
    assert header[:4] == b"\x7fELF", header[:4]
    ei_class = header[4]
    e_machine = int.from_bytes(header[18:20], "little")
    return ei_class, e_machine


@pytest.mark.integration
def test_m11_r2_static_pipeline_on_an_aarch64_target() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — arch Gate not run (skip != pass)")
    if _arm_compiler() is None:
        pytest.skip("aarch64-linux-gnu-gcc missing — cannot build ARM64 fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_aarch64_elf(Path(tmp))

        # Independent of r2: the fixture really is a 64-bit AArch64 ELF.
        ei_class, e_machine = _elf_machine(binary)
        assert ei_class == 2, ei_class  # ELFCLASS64
        assert e_machine == _EM_AARCH64, e_machine

        assert client.open(binary, timeout=60.0).get("opened") is True

        # Strings: the marker literal is recovered with a mapped address.
        strings = client.run(binary, ["izj"], timeout=60.0)
        assert strings.get("parsed") is True
        marker = [s for s in strings["items"] if s.get("string") == _MARKER]
        assert marker, [s.get("string") for s in strings["items"]]
        assert isinstance(marker[0].get("address"), dict)

        # Imports: the libc calls resolve as functions even cross-arch.
        imports = client.run(binary, ["iij"], timeout=60.0)
        assert imports.get("parsed") is True
        import_names = {str(i.get("name")) for i in imports["items"]}
        assert {"puts", "strcmp"} <= import_names, import_names

        # Functions: analysis discovers the named function and main.
        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        assert funcs.get("parsed") is True
        assert funcs.get("count", 0) >= 5
        func_names = [str(f.get("name")) for f in funcs["items"]]
        check = next(
            (f for f in funcs["items"] if "check_password" in str(f.get("name"))), None
        )
        assert check is not None, func_names
        assert any("main" in n for n in func_names), func_names
        check_va = check.get("offset")
        assert isinstance(check_va, int)
        assert isinstance(check.get("address"), dict)

        # Disassembly is genuine ARM64: the prologue stores the frame/link
        # registers, the compare/branch pair and the bl into strcmp all appear.
        # These mnemonics cannot be produced by an x86-64 decode.
        disasm = client.disasm(binary, check_va, count=48, timeout=60.0)
        assert disasm.get("parsed") is True
        assert disasm.get("count", 0) >= 1
        ops = " \n".join(str(i.get("disasm", "")) for i in disasm["items"])
        assert "stp x29" in ops, ops[:600]
        assert "bl " in ops, ops[:600]
        assert ("b.ne" in ops) or ("b.eq" in ops), ops[:600]
        assert (" sp" in ops) or ("x29" in ops), ops[:600]
        assert "strcmp" in ops, ops[:600]
        inbound_call = any(
            x.get("type") == "CALL"
            for item in disasm["items"]
            for x in (item.get("xrefs") or [])
        )
        assert inbound_call, "expected an inbound CALL xref on the ARM64 function entry"

        # Outbound xref graph is populated with mapped source/target addresses.
        out = client.xrefs_from(binary, check_va, timeout=60.0)
        assert out.get("parsed") is True
        assert out.get("count", 0) >= 1
        assert any(
            isinstance(x.get("at_address"), dict) and isinstance(x.get("ref_address"), dict)
            for x in out["items"]
        ), out["items"][:6]
