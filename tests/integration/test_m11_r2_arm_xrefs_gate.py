"""M11 r2 targeted xrefs gate across ARM architectures (AArch64 + ARM32).

The x86-64 xrefs gate proves axtj/axffj narrow inbound/outbound edges, and the
arch gate proves the *static* pipeline runs cross-arch, but nothing proves the
targeted xref semantics survive a different call encoding. On x86 a call is the
``call`` instruction; on ARM it is branch-with-link (``bl``), a different opcode
class entirely, and r2's CALL classification plus the client's at/ref address
mapping have to hold there too or ``r2.xrefs_to``/``xrefs_from`` would silently
misreport the call graph on every ARM binary.

This gate cross-compiles the same caller/callee crackme to AArch64 and 32-bit
ARM, independently confirms the ELF machine, then asserts on each target:

- ``xrefs_to(check_password)`` narrows to exactly one inbound CALL, whose
  enclosing function is ``main`` (named, at main's address), whose call site is
  inside main's body, and whose opcode is a genuine ``bl`` -- something no x86
  decode emits;
- ``xrefs_from(check_password)`` lists the outbound CALLs to ``strcmp`` and
  ``puts`` by name, with both endpoints mapped to Address objects;
- the two directions agree: the call site ``main`` uses to reach
  ``check_password`` (axffj ``at``) is the same address axtj reports inbound.

Skips honestly when radare2/rizin or the specific cross compiler is missing.
skip != pass.
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
    if (strcmp(s, "r2-arm-xrefs-marker-5e7a") == 0) {
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

# arch -> (cross compiler, extra cc flags, expected ei_class, expected e_machine)
_TARGETS = {
    "aarch64": ("aarch64-linux-gnu-gcc", (), 2, 183),  # ELFCLASS64, EM_AARCH64
    "arm32": ("arm-linux-gnueabihf-gcc", ("-marm",), 1, 40),  # ELFCLASS32, EM_ARM (A32)
}


def _build(compiler: str, extra: tuple[str, ...], dest: Path) -> Path:
    src = dest / "fixture.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "fixture.arm"
    subprocess.run(  # noqa: S603 - fixed args, local cross compiler
        [compiler, "-O0", "-fno-inline", *extra, "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


def _elf_machine(binary: Path) -> tuple[int, int]:
    header = binary.read_bytes()[:20]
    assert header[:4] == b"\x7fELF", header[:4]
    return header[4], int.from_bytes(header[18:20], "little")


@pytest.mark.integration
@pytest.mark.parametrize("arch", sorted(_TARGETS))
def test_m11_r2_targeted_xrefs_on_arm(arch: str) -> None:
    compiler_name, extra, want_class, want_machine = _TARGETS[arch]
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — ARM xrefs Gate not run (skip != pass)")
    compiler = shutil.which(compiler_name)
    if compiler is None:
        pytest.skip(f"{compiler_name} missing — cannot build {arch} fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build(compiler, extra, Path(tmp))

        # Independent of r2: the fixture really is the ARM variant we expect.
        ei_class, e_machine = _elf_machine(binary)
        assert (ei_class, e_machine) == (want_class, want_machine), (ei_class, e_machine)

        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        assert funcs.get("parsed") is True
        by_name = {str(f.get("name")): f for f in funcs["items"]}
        check = next((f for n, f in by_name.items() if "check_password" in n), None)
        main = next(
            (f for n, f in by_name.items() if n == "main" or n.endswith(".main")), None
        )
        assert check is not None and main is not None, list(by_name)
        check_va = check["offset"]
        main_va = main["offset"]
        assert isinstance(check_va, int) and isinstance(main_va, int)

        # Inbound: exactly one CALL, from main, at a site inside main's body, and
        # the opcode is a real ARM branch-with-link -- the whole point of this
        # gate is that CALL classification survives the bl encoding.
        to = client.xrefs_to(binary, check_va, timeout=60.0)
        assert to.get("parsed") is True
        assert to.get("count") == 1, to.get("items")
        assert to.get("address_va") == check_va
        edge = to["items"][0]
        assert edge.get("type") == "CALL", edge
        assert str(edge.get("fcn_name")) == "main", edge
        assert edge.get("fcn_addr") == main_va, edge
        assert isinstance(edge.get("from"), int) and edge["from"] >= main_va, edge
        assert isinstance(edge.get("from_address"), dict), edge
        assert "check_password" in str(edge.get("refname")), edge
        assert "bl" in str(edge.get("opcode")).split(), edge  # ARM branch-with-link

        # Outbound: the two libc calls resolve by name, both endpoints mapped.
        frm = client.xrefs_from(binary, check_va, timeout=60.0)
        assert frm.get("parsed") is True
        assert frm.get("address_va") == check_va
        assert frm["commands"][-1] == f"axffj @ {check_va}"
        call_names = {
            str(i.get("name")) for i in frm["items"] if str(i.get("type")) == "CALL"
        }
        assert any("strcmp" in n for n in call_names), call_names
        assert any("puts" in n for n in call_names), call_names
        for item in frm["items"]:
            assert isinstance(item.get("at_address"), dict), item
            assert isinstance(item.get("ref_address"), dict), item

        # Bidirectional agreement: main's outbound CALL into check_password and
        # the inbound edge axtj reports describe one call edge at one address.
        frm_main = client.xrefs_from(binary, main_va, timeout=60.0)
        call_to_check = [
            i
            for i in frm_main.get("items", [])
            if str(i.get("type")) == "CALL" and i.get("ref") == check_va
        ]
        assert call_to_check, [
            (str(i.get("name")), i.get("type"), i.get("ref"))
            for i in frm_main.get("items", [])
        ]
        assert "check_password" in str(call_to_check[0].get("name")), call_to_check[0]
        inbound_sites = {
            i.get("from") for i in to.get("items", []) if i.get("type") == "CALL"
        }
        assert call_to_check[0].get("at") in inbound_sites, (
            call_to_check[0].get("at"),
            inbound_sites,
        )
