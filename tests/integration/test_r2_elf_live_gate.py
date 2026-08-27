"""r2 live gate on a real ELF, so the radare2 line has coverage on the Linux core.

The only other live r2 gate (``test_m11_r2_live_gate``) needs a Windows PE
fixture that does not ship with the Linux core, so on this platform radare2 --
installed, cross-platform, and the whole non-PE static-analysis line -- had zero
end-to-end coverage: every r2 test mocked the subprocess. This compiles a tiny
ELF with the system C compiler and drives the real one-shot r2 pipeline through
it (argv build, JSON extraction past the banner, whitelist, Address mapping).

skip != pass: no r2 or no C compiler skips, it does not quietly succeed. The PE
RVA mapping already has its own gate; here the binary is ELF, so items carry a
plain ``va`` and that is exactly what is asserted.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error

_STRING_MARKER = "r2-elf-gate-marker"

_SOURCE = f"""
#include <stdio.h>
const char *BANNER = "{_STRING_MARKER}";
int helper(int x) {{ return x * 3 + 1; }}
int compute(int n) {{
    int total = 0;
    for (int i = 0; i < n; i++) total += helper(i);
    return total;
}}
int main(void) {{ printf("%s %d\\n", BANNER, compute(7)); return 0; }}
"""


def _compile_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build the ELF fixture — skip != pass")
    source = tmp_path / "r2demo.c"
    source.write_text(_SOURCE, encoding="utf-8")
    binary = tmp_path / "r2demo"
    # -no-pie so functions land at fixed low VAs the assertions can read without
    # having to reason about load bias; -O0 so helper/compute survive inlining.
    result = subprocess.run(  # noqa: S603 - fixed argv, compiler discovered on PATH
        [compiler, "-O0", "-no-pie", "-o", str(binary), str(source)],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0 or not binary.is_file():
        pytest.skip(
            "C compiler could not build a -no-pie ELF here "
            f"({result.stderr.decode('utf-8', 'replace')[:200]}) — skip != pass"
        )
    return binary


def _named(items: list[dict], needle: str) -> dict | None:
    for item in items:
        if needle in str(item.get("name", "")):
            return item
    return None


@pytest.mark.integration
def test_r2_open_identifies_a_real_elf(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    opened = client.open(binary, timeout=60.0)
    assert opened["opened"] is True
    # ``i`` prints the container format; for our fixture that is ELF, which
    # proves the argv/one-shot path actually reached r2 and came back.
    assert "elf" in opened["info"].casefold()


@pytest.mark.integration
def test_r2_functions_map_to_addresses_on_a_real_elf(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert funcs["parsed"] is True
    assert funcs.get("count", 0) >= 1
    items = funcs["items"]

    # The functions we wrote must be discovered, each with a usable VA. ELF has
    # no PE ImageBase, so the Address is a plain va (rva is a PE-only field).
    for want in ("helper", "compute", "main"):
        found = _named(items, want)
        assert found is not None, f"radare2 did not report {want}: {[i.get('name') for i in items]}"
        address = found.get("address")
        assert isinstance(address, dict) and isinstance(address.get("va"), int)
        assert address["va"] > 0
        assert "rva" not in address, "ELF items must not fabricate a PE RVA"


@pytest.mark.integration
def test_r2_disasm_and_xrefs_run_against_a_real_function(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
    target = _named(funcs["items"], "compute") or _named(funcs["items"], "helper")
    assert target is not None, "no function to disassemble"
    va = target["address"]["va"]

    disasm = client.disasm(binary, va, count=8, timeout=60.0)
    assert disasm["parsed"] is True
    assert disasm.get("count", 0) >= 1
    # The request address round-trips as an Address, and the rows carry opcodes:
    # this is the analysis text a caller reads to find where a function ends.
    assert disasm["address"]["va"] == va
    assert any(row.get("opcode") for row in disasm["items"])

    xrefs = client.xrefs(binary, va, timeout=60.0)
    assert xrefs["parsed"] is True
    # Every mapped xref endpoint is a structured Address, never a bare int.
    for row in xrefs["items"]:
        edge = row.get("address")
        if edge is not None:
            assert isinstance(edge, dict) and isinstance(edge.get("va"), int)

    # These are refs *to* compute, and compute is called from main, so the list
    # must not be empty and its callers must sit in main -- not a program-wide
    # dump. `axj @ addr` ignores the seek and returns every ref in the binary;
    # `axtj @ addr` honours it. Lock the difference: the refs-to count must be
    # strictly below the whole-binary axj count, or the seek was dropped again.
    assert xrefs.get("count", 0) >= 1, "compute is called from main; refs-to must not be empty"
    callers = [str(row.get("fcn_name", "")) for row in xrefs["items"]]
    assert any("main" in caller for caller in callers), (
        f"expected main among compute's callers, got: {callers}"
    )
    assert any("compute" in str(row.get("opcode", "")) for row in xrefs["items"])
    program_wide = client.run(binary, ["aa", f"axj @ {va}"], timeout=60.0)
    assert program_wide["parsed"] is True
    assert xrefs["count"] < program_wide.get("count", 0), (
        "axtj must return only refs to the address; a count equal to the "
        "program-wide axj count means the seek was ignored"
    )


@pytest.mark.integration
def test_r2_strings_imports_exports_map_on_a_real_elf(tmp_path: Path) -> None:
    """The listing side of the r2 line (izj/iij/iEj) had no live ELF coverage.

    r2_strings/imports/exports are separate service tools; the functions gate
    only drives aflj. Prove each returns parsed items with the unified Address
    mapping on a real binary: a known string we compiled in, a libc import, and
    one of our own functions as an export.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    strings = client.run(binary, ["izj"], timeout=60.0)
    assert strings["parsed"] is True
    marker = next(
        (s for s in strings["items"] if _STRING_MARKER in str(s.get("string", ""))),
        None,
    )
    assert marker is not None, (
        f"compiled-in string missing: {[s.get('string') for s in strings['items']]}"
    )
    assert isinstance(marker.get("address"), dict)
    assert isinstance(marker["address"].get("va"), int)

    imports = client.run(binary, ["iij"], timeout=60.0)
    assert imports["parsed"] is True
    assert imports.get("count", 0) >= 1
    for item in imports["items"]:
        assert isinstance(item.get("address"), dict), "import lacks a structured Address"
    assert _named(imports["items"], "__libc_start_main") is not None, (
        f"expected a libc import: {[i.get('name') for i in imports['items']]}"
    )

    exports = client.run(binary, ["iEj"], timeout=60.0)
    assert exports["parsed"] is True
    ours = _named(exports["items"], "main") or _named(exports["items"], "compute")
    assert ours is not None, (
        f"none of our functions were exported: {[e.get('name') for e in exports['items']]}"
    )
    assert isinstance(ours.get("address"), dict)
    assert isinstance(ours["address"].get("va"), int)


@pytest.mark.integration
def test_r2_rejects_a_command_off_the_whitelist_even_live(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    # The whitelist is the only thing standing between an r2 tool call and
    # arbitrary r2 command execution; prove it holds on the live path, not just
    # in the mocked unit test. ``!`` shells out in r2, which is exactly what
    # must never leave this process.
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["!id"], timeout=60.0)
    assert caught.value.code == "invalid_params"
