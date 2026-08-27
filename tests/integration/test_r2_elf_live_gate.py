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


_RODATA_MARKER = "r2-rodata-visible-marker"
_HIDDEN_MARKER = "r2-whole-file-only-marker"

# A string in .rodata (izj and izzj both see it) plus one forced into a
# non-loaded custom section: izj scans only data sections, so it never looks
# there, but the whole-file scan does. This is the packer-hides-strings shape
# the whole=true option exists for, reduced to a deterministic fixture.
_HIDDEN_SECTION_SOURCE = f"""
#include <stdio.h>
const char *VISIBLE = "{_RODATA_MARKER}";
__attribute__((used, section(".r2hidden")))
static const char HIDDEN[] = "{_HIDDEN_MARKER}";
int main(void) {{ printf("%s\\n", VISIBLE); return (int)HIDDEN[0]; }}
"""


def _compile_hidden_section_elf(tmp_path: Path) -> Path:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build the ELF fixture — skip != pass")
    source = tmp_path / "r2hidden.c"
    source.write_text(_HIDDEN_SECTION_SOURCE, encoding="utf-8")
    binary = tmp_path / "r2hidden"
    result = subprocess.run(  # noqa: S603 - fixed argv, compiler discovered on PATH
        [compiler, "-O0", "-no-pie", "-o", str(binary), str(source)],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0 or not binary.is_file():
        detail = result.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"C compiler could not build the hidden-section ELF ({detail}) — skip != pass")
    return binary


def _has_string(items: list[dict], marker: str) -> bool:
    return any(marker in str(item.get("string", "")) for item in items)


@pytest.mark.integration
def test_r2_strings_whole_recovers_a_string_izj_misses(tmp_path: Path) -> None:
    """whole=true (izzj) must recover a string the data-section scan (izj) misses.

    The whole point of the option is a packer that hides its payload strings
    outside the sections izj scans. Compile a marker into a non-loaded custom
    section, then prove the default scan does not see it while the whole-file
    scan does -- and that the recovered entry still maps to a real section and
    Address, so it is not a mangled byte run. Without the miss/find pair the
    option would be indistinguishable from the default and could rot silently.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_hidden_section_elf(tmp_path)

    # Default: data-section scan. It must find the .rodata string and must NOT
    # find the one buried in the non-loaded section.
    izj = client.run(binary, ["izj"], timeout=60.0)
    assert izj["parsed"] is True
    assert _has_string(izj["items"], _RODATA_MARKER), (
        f"the .rodata marker was not in the default scan: "
        f"{[s.get('string') for s in izj['items']]}"
    )
    assert not _has_string(izj["items"], _HIDDEN_MARKER), (
        "the hidden-section marker leaked into the data-section scan; the fixture "
        "no longer distinguishes izj from izzj on this radare2"
    )

    # Whole-file scan: a superset that must recover both markers.
    izzj = client.run(binary, ["izzj"], timeout=60.0)
    assert izzj["parsed"] is True
    assert _has_string(izzj["items"], _RODATA_MARKER)
    assert _has_string(izzj["items"], _HIDDEN_MARKER), (
        f"the whole-file scan did not recover the hidden-section string: "
        f"{[s.get('string') for s in izzj['items']]}"
    )
    # It is a superset: it cannot report fewer strings than the data-section scan.
    assert izzj.get("count", 0) >= izj.get("count", 0)

    hidden = next(
        item for item in izzj["items"] if _HIDDEN_MARKER in str(item.get("string", ""))
    )
    # The recovered string still carries its section name and a structured
    # Address -- it is a real find, not a stray byte run mislabelled as text.
    assert hidden.get("section") == ".r2hidden"
    assert isinstance(hidden.get("address"), dict)
    assert isinstance(hidden["address"].get("va"), int)


@pytest.mark.integration
def test_r2_sections_map_on_a_real_elf(tmp_path: Path) -> None:
    """The section layout (iSj) had no live ELF coverage.

    r2.sections is a separate service tool; nothing else drives iSj. Prove it
    returns parsed items with the unified Address mapping on a real binary: the
    executable .text section must be present, sit at a usable VA, and be marked
    executable in its perm string -- the map a caller reads before choosing an
    address for disasm.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    sections = client.run(binary, ["iSj"], timeout=60.0)
    assert sections["parsed"] is True
    assert sections.get("count", 0) >= 1
    text = _named(sections["items"], ".text")
    assert text is not None, (
        f"radare2 did not report a .text section: {[s.get('name') for s in sections['items']]}"
    )
    address = text.get("address")
    assert isinstance(address, dict) and isinstance(address.get("va"), int)
    assert address["va"] > 0
    assert "rva" not in address, "ELF sections must not fabricate a PE RVA"
    # .text is code, so radare2's perm string must mark it executable; this is
    # the field a caller reads to tell code sections from data.
    assert "x" in str(text.get("perm", "")), (
        f".text should be executable, got perm={text.get('perm')!r}"
    )


@pytest.mark.integration
def test_r2_symbols_list_the_whole_table_on_a_real_elf(tmp_path: Path) -> None:
    """The full symbol table (isj) had no live ELF coverage.

    r2.symbols is a separate service tool; nothing else drives isj. Prove it
    returns parsed items with the unified Address mapping on a real binary: the
    functions we wrote must all appear as FUNC symbols with usable VAs, and the
    table must be a superset of the export list -- it is where local symbols and
    the FUNC entries that never made the export table are read.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    symbols = client.run(binary, ["isj"], timeout=60.0)
    assert symbols["parsed"] is True
    assert symbols.get("count", 0) >= 1

    for want in ("helper", "compute", "main"):
        found = _named(symbols["items"], want)
        assert found is not None, (
            f"radare2 did not report {want} in the symbol table: "
            f"{[s.get('name') for s in symbols['items']]}"
        )
        address = found.get("address")
        assert isinstance(address, dict) and isinstance(address.get("va"), int)
        assert address["va"] > 0
        assert "rva" not in address, "ELF symbols must not fabricate a PE RVA"
        # These are our own functions, so radare2 must type them as FUNC and not
        # flag them imported -- that is what separates them from libc thunks.
        assert str(found.get("type", "")).upper() == "FUNC"
        assert found.get("is_imported") is not True

    # The symbol table is the superset r2.exports slices: every export must also
    # be a symbol, so isj cannot report fewer entries than iEj.
    exports = client.run(binary, ["iEj"], timeout=60.0)
    assert exports["parsed"] is True
    assert symbols["count"] >= exports.get("count", 0), (
        "isj must be a superset of iEj; a symbol table smaller than the export "
        "list means isj was not the full table"
    )


@pytest.mark.integration
def test_r2_relocations_list_the_fixup_table_on_a_real_elf(tmp_path: Path) -> None:
    """The relocation table (irj) had no live ELF coverage.

    r2.relocations is a separate service tool; nothing else drives irj. A
    dynamically linked ELF that calls printf must carry a relocation binding
    that symbol's GOT/PLT slot, so prove irj returns parsed items with the
    unified Address mapping on a real binary and that the imported symbol shows
    up in the fixup table -- the slot r2.xrefs then traces the callers of.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    relocs = client.run(binary, ["irj"], timeout=60.0)
    assert relocs["parsed"] is True
    assert relocs.get("count", 0) >= 1, "a dynamically linked ELF must have relocations"

    # Every relocation names the slot address it patches; the enrichment must
    # attach a structured Address built from vaddr, with a plain va (no PE RVA).
    for item in relocs["items"]:
        address = item.get("address")
        assert isinstance(address, dict), "relocation lacks a structured Address"
        assert isinstance(address.get("va"), int)
        assert "rva" not in address, "ELF relocations must not fabricate a PE RVA"
        assert "type" in item, "relocation entry must carry its reloc type"

    # printf is called from main and resolved through a PLT/GOT relocation, so
    # the imported symbol must appear in the fixup table.
    printf = _named(relocs["items"], "printf") or _named(relocs["items"], "puts")
    assert printf is not None, (
        "expected a libc call relocation (printf/puts): "
        f"{[r.get('name') for r in relocs['items']]}"
    )


@pytest.mark.integration
def test_r2_libraries_list_the_linked_dependencies_on_a_real_elf(tmp_path: Path) -> None:
    """The linked-library list (ilj) had no live ELF coverage.

    r2.libraries parses ilj's JSON string array itself (the shared enrich path
    only shapes object arrays), so exercise that parsing on a real binary: a
    dynamically linked ELF must name libc.so.6 in its DT_NEEDED list, and the
    same fixture built ``-static`` must come back with an empty list -- the
    finding that nothing is resolved at load time.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    binary = _compile_elf(tmp_path)

    dynamic = client.libraries(binary, timeout=60.0)
    assert dynamic["count"] >= 1, "a dynamically linked ELF must list dependencies"
    assert dynamic["module"] == binary.name
    assert any("libc" in name for name in dynamic["libraries"]), (
        f"expected libc in the dependency list: {dynamic['libraries']}"
    )

    # The static counterpart resolves libc at link time, so ilj is empty. The
    # -static toolchain is not always installed; a build failure is a skip, not
    # a false assertion.
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    assert compiler is not None  # _compile_elf would have skipped otherwise
    static_bin = tmp_path / "r2demo_static"
    built = subprocess.run(  # noqa: S603 - fixed argv, compiler discovered on PATH
        [compiler, "-O0", "-no-pie", "-static", "-o", str(static_bin), str(tmp_path / "r2demo.c")],
        capture_output=True,
        timeout=120,
    )
    if built.returncode == 0 and static_bin.is_file():
        static = client.libraries(static_bin, timeout=60.0)
        assert static["libraries"] == [], (
            f"a static binary links nothing at load: {static['libraries']}"
        )
        assert static["count"] == 0


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
