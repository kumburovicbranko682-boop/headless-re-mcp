"""M11 r2 architecture gate: the static pipeline on a 32-bit ARM (A32) target.

The AArch64 gate proves r2 handles one non-x86 architecture; 32-bit ARM is a
genuinely different one -- a distinct instruction encoding still shipped in
embedded firmware and older Android native libraries -- so it earns its own
proof rather than riding on the 64-bit result. This gate cross-compiles the
crackme to ARM (A32, forced with -marm) and drives strings, imports, function
recovery, disassembly and the outbound xref graph against it.

Before trusting r2 it confirms the fixture really is a 32-bit ARM ELF from the
header (ELFCLASS32 + EM_ARM), then asserts r2 disassembles real A32: the
register-list ``push {..., lr}`` / ``pop {..., pc}`` frame ops, which neither
x86-64 nor AArch64 (it uses stp/ldp) can emit. skip != pass when radare2/rizin
or the arm cross compiler is missing.
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
    if (strcmp(s, "r2-arm32-gate-marker-5e8b") == 0) {
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
_MARKER = "r2-arm32-gate-marker-5e8b"
_EM_ARM = 40  # ELF e_machine value for 32-bit ARM.


def _arm_compiler() -> str | None:
    return shutil.which("arm-linux-gnueabihf-gcc") or shutil.which("arm-linux-gnueabi-gcc")


def _build_arm32_elf(dest: Path) -> Path:
    compiler = _arm_compiler()
    assert compiler is not None
    src = dest / "fixture.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "fixture.arm32"
    # -marm forces A32 (not Thumb) so the register-list frame ops appear.
    subprocess.run(  # noqa: S603 - fixed args, local cross compiler
        [compiler, "-O0", "-fno-inline", "-marm", "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


def _elf_machine(binary: Path) -> tuple[int, int]:
    """Return (ei_class, e_machine) straight from the ELF header."""
    header = binary.read_bytes()[:20]
    assert header[:4] == b"\x7fELF", header[:4]
    return header[4], int.from_bytes(header[18:20], "little")


@pytest.mark.integration
def test_m11_r2_static_pipeline_on_an_arm32_target() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — arm32 Gate not run (skip != pass)")
    if _arm_compiler() is None:
        pytest.skip("arm-linux-gnueabihf-gcc missing — cannot build ARM32 fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_arm32_elf(Path(tmp))

        # Independent of r2: the fixture really is a 32-bit ARM ELF.
        ei_class, e_machine = _elf_machine(binary)
        assert ei_class == 1, ei_class  # ELFCLASS32
        assert e_machine == _EM_ARM, e_machine

        assert client.open(binary, timeout=60.0).get("opened") is True

        # Strings: the marker literal is recovered with a mapped address.
        strings = client.run(binary, ["izj"], timeout=60.0)
        assert strings.get("parsed") is True
        marker = [s for s in strings["items"] if s.get("string") == _MARKER]
        assert marker, [s.get("string") for s in strings["items"]]
        assert isinstance(marker[0].get("address"), dict)

        # Imports: the libc calls resolve as functions even on 32-bit ARM.
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

        # Disassembly is genuine A32: the prologue and epilogue move a register
        # list to/from the stack (push {..., lr} / pop {..., pc}) and the body
        # branches with bl. These forms are unique to 32-bit ARM.
        disasm = client.disasm(binary, check_va, count=48, timeout=60.0)
        assert disasm.get("parsed") is True
        assert disasm.get("count", 0) >= 1
        ops = " \n".join(str(i.get("disasm", "")) for i in disasm["items"])
        assert "push {" in ops, ops[:600]
        assert "pop {" in ops, ops[:600]
        assert "bl " in ops, ops[:600]
        assert "strcmp" in ops, ops[:600]
        inbound_call = any(
            x.get("type") == "CALL"
            for item in disasm["items"]
            for x in (item.get("xrefs") or [])
        )
        assert inbound_call, "expected an inbound CALL xref on the ARM32 function entry"

        # Outbound xref graph is populated with mapped source/target addresses.
        out = client.xrefs_from(binary, check_va, timeout=60.0)
        assert out.get("parsed") is True
        assert out.get("count", 0) >= 1
        assert any(
            isinstance(x.get("at_address"), dict) and isinstance(x.get("ref_address"), dict)
            for x in out["items"]
        ), out["items"][:6]
