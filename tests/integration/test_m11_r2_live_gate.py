"""M11 r2 live gate: address mapping, disassembly, xrefs. skip≠pass when r2 missing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.backends.r2.mapping import elf_preferred_base
from headless_re_mcp.core.models import Architecture

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _r2_fixture() -> Path | None:
    """A PE for r2 to map, preferring the Windows-built gate fixture.

    r2 is a portable static backend, so it analyses a PE the same way on
    Linux as on Windows. The primary fixture is generated on the Windows CI
    and is absent from a plain checkout; falling back to a committed PE keeps
    this gate a real pass on Linux instead of an always-skip that only ever
    exercised the backend on one platform.
    """
    primary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if primary.is_file():
        return primary
    committed = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
    return committed if committed.is_file() else None


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture()
    if fixture is None:
        pytest.skip("no PE fixture available for r2 — live Gate not run (skip≠pass)")

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    # aa+aac is what r2.functions runs: aa analyses only entry0 and symbols,
    # while aac walks the call graph to recover the functions a stripped or
    # packed PE hides from it. Drive the same commands the tool does so the gate
    # exercises the real discovery path, not a shallow one that lists a handful.
    funcs = client.run(fixture, ["aa", "aac", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        assert item["address"].get("module") == fixture.name

    # The raw entry key the r2.functions docstring promises must survive whatever
    # r2 is installed. r2 6.x renamed aflj's entry from `offset` to `addr`; the
    # adapter restores `offset` so a caller reads the documented field on any r2,
    # and asserting it here against the real tool is what catches a future rename
    # the alias does not yet cover -- a class of drift CI's pinned r2 hides.
    assert "offset" in item, "r2.functions dropped its documented offset key"
    assert item["offset"] == item["address"]["va"]

    # Past function listing into the analysis core. disasm (pdj) at a real
    # function entry runs the parameterized command past the whitelist, r2
    # returns instructions, and the request address round-trips through the
    # address mapping -- the surface a caller actually reverse-engineers with.
    va = item["address"]["va"]
    assert isinstance(va, int)
    disasm = client.disasm(fixture, va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count", 0) >= 1
    assert disasm.get("address_va") == va
    assert disasm["address"]["va"] == va
    instruction = disasm["items"][0]
    assert "opcode" in instruction or "disasm" in instruction

    # xrefs (axtj) exercises the second parameterized whitelist command; the
    # reference count is data-dependent (the first listed function is often the
    # entry point, which nothing references), so only its shape and the
    # round-tripped request address are asserted -- axtj answers [] for a
    # referent-free address, which must still read back as parsed with count 0.
    xrefs = client.xrefs(fixture, va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert isinstance(xrefs.get("count"), int)
    assert xrefs.get("address_va") == va

    # imports (iij) is the other tool whose raw key drifted: r2 6.x renamed the
    # import library from `lib` to `libname`, and unlike an address the library
    # name is recoverable from no other field. A real PE imports from at least
    # one DLL, so the documented `lib` must be present and name a library --
    # pinning the adapter's restore against the installed r2, not just a stub.
    imports = client.run(fixture, ["iij"], timeout=60.0)
    assert imports.get("parsed") is True
    import_items = imports.get("items") or []
    assert import_items, "r2 found no imports in the PE"
    assert isinstance(import_items[0].get("address"), dict)
    assert any(
        isinstance(row.get("lib"), str) and row["lib"] for row in import_items
    ), "no import carried the documented lib key"

    # strings (izj) is the last whitelisted listing whose documented raw keys
    # (string, section, type, vaddr) no live gate demanded of a real r2. offset
    # and lib both drifted between r2 5.x and 6.x before their aliases; this is
    # the tripwire that notices when the string keys drift too. The committed
    # fixture embeds its own literals, so the listing is non-empty by
    # construction and each documented key can be asserted, plus the mapped
    # address the enrichment adds.
    strings = client.run(fixture, ["izj"], timeout=60.0)
    assert strings.get("parsed") is True
    string_items = strings.get("items") or []
    assert string_items, "r2 found no strings in the PE"
    first_string = string_items[0]
    for key in ("string", "section", "type", "vaddr"):
        assert key in first_string, f"izj dropped the documented {key} key"
    # Value-based, not shape-only: izj rows also carry paddr, which the
    # enrichment would fall back to if vaddr stopped being read -- an address
    # dict would still appear, holding a file offset instead of a va.
    assert first_string["address"]["va"] == first_string["vaddr"]

    # exports (iEj) on this fixture pins the empty-but-honest shape: a console
    # exe exports nothing, and r2 answers [] -- which must read back as a
    # parsed, zero-count listing, not a parse failure or an invented row. The
    # ELF gate below covers the populated side of the same contract.
    exports = client.run(fixture, ["iEj"], timeout=60.0)
    assert exports.get("parsed") is True
    assert exports.get("count") == 0
    assert exports.get("items") == []


@pytest.mark.integration
def test_m11_r2_live_elf_address_mapping(tmp_path: Path) -> None:
    """r2 on an ELF gets rva/module/arch, not the PE-only enrichment it used to.

    The PE gate above only ever proved the mapping on Windows' native format;
    on Linux the session target is usually an ELF, for which the enrichment used
    to read no load base and hand back va-only addresses. Compile a real non-PIE
    ELF (ET_EXEC at a fixed base, so rva is meaningful; a PIE would legitimately
    be base-less and va-only) and drive the same aa+aac+aflj the r2.functions
    tool runs, then assert the load base the ELF program headers declare threads
    through to a real function's rva. Measured against the installed r2, this is
    what catches an ELF-specific parse or key drift the synthetic unit fixture
    cannot. Skips honestly (skip != pass) when r2 or a C compiler is absent.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler to build an ELF fixture — live Gate not run (skip≠pass)")

    source = tmp_path / "elf_fixture.c"
    # greet is a non-static global (so it lands in the symbol table r2 lists as
    # exports) returning a planted literal (so .rodata holds a known string).
    source.write_text(
        "int helper(int x){return x+1;}\n"
        'const char *greet(void){return "hello elf strings";}\n'
        "int main(void){return helper(41);}\n"
    )
    fixture = tmp_path / "elf_fixture"
    build = subprocess.run(
        [gcc, "-no-pie", "-O0", "-o", str(fixture), str(source)],
        capture_output=True,
        text=True,
        timeout=120.0,
    )
    if build.returncode != 0 or not fixture.is_file():
        # -no-pie can be unsupported on a hardened toolchain (some distros build
        # gcc PIE-only). That is a toolchain limitation, not an r2 regression, so
        # skip rather than fail -- the unit tests still pin the parser.
        pytest.skip(f"could not build a non-PIE ELF ({build.stderr.strip()[:200]}) — skip≠pass")

    funcs = client.run(fixture, ["aa", "aac", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    # The ELF program headers put ET_EXEC's first PT_LOAD at a fixed base (the
    # SysV x86-64 default is 0x400000); the enrichment must have read it from the
    # ELF, not from a PE header it does not have.
    image_base = funcs.get("image_base")
    assert isinstance(image_base, int) and image_base > 0, funcs.get("image_base")
    assert funcs.get("architecture") == "x64", funcs.get("architecture")

    # At least one recovered function must carry an rva computed from that base,
    # with the module named -- the coordinate the PE path already produced and
    # the ELF path used to drop. Data-independent: every function in an ET_EXEC
    # sits above the load base, so the mapping applies regardless of which
    # functions r2's analysis happens to name.
    mapped = [
        item
        for item in funcs["items"]
        if isinstance(item.get("address"), dict) and "rva" in item["address"]
    ]
    assert mapped, "no ELF function carried an rva mapped through the load base"
    sample = mapped[0]
    assert sample["address"]["module"] == fixture.name
    assert sample["address"]["va"] - image_base == sample["address"]["rva"]

    # disasm at a real ELF function entry round-trips the request address through
    # the same mapping, proving the parameterized pdj path works on ELF too.
    va = sample["address"]["va"]
    disasm = client.disasm(fixture, va, count=4, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("address_va") == va
    assert disasm["address"]["rva"] == va - image_base

    # xrefs (axtj) on ELF exercises the aac+axtj path where it matters most: the
    # call graph aac builds is what lets axtj recover a function's callers, and
    # the fixture wires exactly one -- main calls helper -- so the reference is
    # data-independent rather than depending on which functions analysis names.
    # The PE gate can only prove xrefs against a referent-free entry (count 0);
    # this pins the populated side, with the caller's address threaded through
    # the same ELF load base as everything above.
    helper_fns = [
        item
        for item in funcs["items"]
        if "helper" in (item.get("name") or "") and isinstance(item.get("address"), dict)
    ]
    assert helper_fns, "r2 did not recover the helper function to take xrefs of"
    helper_va = helper_fns[0]["address"]["va"]
    xrefs = client.xrefs(fixture, helper_va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert xrefs.get("address_va") == helper_va
    assert xrefs.get("count", 0) >= 1, "aac+axtj found no caller of a function main calls"
    xref_rows = xrefs.get("items") or []
    assert any(
        row.get("type") == "CALL" and "main" in (row.get("fcn_name") or "")
        for row in xref_rows
    ), f"the call from main to helper was not among the xrefs: {xref_rows}"
    for row in xref_rows:
        if isinstance(row.get("address"), dict) and "rva" in row["address"]:
            assert row["address"]["rva"] == row["address"]["va"] - image_base

    # imports (iij) on an ELF: the rows carry no lib -- an ELF resolves imports
    # at runtime through DT_NEEDED, not per symbol -- and, measured against a
    # real toolchain, an import reached only through the GOT carries no plt or
    # address either: a trivial gcc build's __libc_start_main row is name-only.
    # This pins exactly what the r2.imports docstring promises for ELF (name
    # always; lib never; address only with a stub), where the first draft of
    # this gate wrongly demanded an address dict of every row. A dynamically
    # linked executable always imports at least the libc startup functions, so
    # the list is non-empty.
    imports = client.run(fixture, ["aa", "iij"], timeout=60.0)
    assert imports.get("parsed") is True
    import_items = imports.get("items") or []
    assert import_items, "r2 found no imports in a dynamically linked ELF"
    for row in import_items:
        assert isinstance(row.get("name"), str) and row["name"]
        assert "lib" not in row, f"an ELF import claimed a lib: {row}"
        # r2 5.x emits a plt: 0 sentinel for these stub-less rows (6.x omits
        # the key); the alias layer must have erased it rather than mapping a
        # fabricated address at va 0 -- on a 5.x CI this line is what proves
        # the normalisation ran against the real tool.
        assert row.get("plt") != 0, f"the plt zero sentinel leaked through: {row}"
        if isinstance(row.get("address"), dict):
            assert row["address"].get("va") != 0, f"a fabricated va-0 address: {row}"

    # exports (iEj): for an ELF r2 lists the global symbols, and the build
    # keeps its symtab (nothing strips it), so the fixture's own non-static
    # greet must surface by name with the documented vaddr, its address mapped
    # through the same load base as everything above. This is the populated
    # counterpart to the PE gate's empty-export contract.
    exports = client.run(fixture, ["iEj"], timeout=60.0)
    assert exports.get("parsed") is True
    export_rows = {
        row.get("name"): row for row in exports.get("items") or [] if isinstance(row, dict)
    }
    assert "greet" in export_rows, f"greet missing from ELF exports: {sorted(export_rows)[:10]}"
    greet = export_rows["greet"]
    assert isinstance(greet.get("vaddr"), int)
    assert greet["address"]["rva"] == greet["vaddr"] - image_base

    # strings (izj): the planted .rodata literal must be recovered verbatim
    # with the documented string/section/type/vaddr keys, its address mapped.
    # Searching for the known literal (rather than trusting item 0) keeps this
    # independent of whatever other strings the toolchain happens to embed.
    strings = client.run(fixture, ["izj"], timeout=60.0)
    assert strings.get("parsed") is True
    planted = [
        row for row in strings.get("items") or [] if row.get("string") == "hello elf strings"
    ]
    assert planted, "the planted .rodata literal was not recovered"
    literal = planted[0]
    for key in ("section", "type", "vaddr"):
        assert key in literal, f"izj dropped the documented {key} key"
    assert literal["address"]["rva"] == literal["vaddr"] - image_base


def _readelf_lowest_load(readelf: str, binary: Path) -> int | None:
    """The lowest PT_LOAD p_vaddr readelf reports, as an independent oracle.

    readelf's -l lines start with the segment type, then file offset, then the
    virtual address, so the third column of each LOAD row is the p_vaddr we
    compare against.
    """
    proc = subprocess.run(
        [readelf, "-l", str(binary)], capture_output=True, text=True, timeout=60.0
    )
    vaddrs: list[int] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "LOAD":
            try:
                vaddrs.append(int(parts[2], 16))
            except ValueError:
                continue
    return min(vaddrs) if vaddrs else None


@pytest.mark.integration
def test_elf_preferred_base_matches_readelf_on_a_real_binary(tmp_path: Path) -> None:
    """Our ELF load base must equal readelf's, cross-checked on real gcc output.

    elf_preferred_base is hand-written binary parsing, and its only current
    proofs share a blind spot. The synthetic unit fixtures write e_phoff /
    e_phentsize / p_vaddr at the very offsets the parser reads them from, so a
    shared wrong offset would pass every unit test yet misread real binaries.
    The r2 ELF gate above only checks self-consistency -- rva == va - base, where
    rva is computed from that same base -- so a wrong-but-positive base slips
    through it too. Nothing measures the base against an independent oracle on a
    real ELF. readelf is that oracle: it reports the program headers from its own
    parser, so requiring our base to equal readelf's lowest PT_LOAD p_vaddr, on a
    genuine gcc build (56-byte phentsize, several LOAD segments, real alignment
    the tiny fixtures lack), pins the parse against reality. A -no-pie build has
    a fixed base; a PIE's first LOAD sits at vaddr 0, which must read back as
    va-only (None), not an invented base. skip != pass: skips when gcc or readelf
    is absent.
    """
    gcc = shutil.which("gcc") or shutil.which("cc")
    readelf = shutil.which("readelf")
    if gcc is None or readelf is None:
        pytest.skip("gcc/readelf not available — ELF base oracle Gate not run (skip != pass)")

    source = tmp_path / "base_fixture.c"
    source.write_text("int main(void){return 0;}\n", encoding="utf-8")

    def _build(name: str, *flags: str) -> Path | None:
        out = tmp_path / name
        proc = subprocess.run(
            [gcc, *flags, "-O0", "-o", str(out), str(source)],
            capture_output=True,
            text=True,
            timeout=120.0,
        )
        return out if proc.returncode == 0 and out.is_file() else None

    non_pie = _build("base_nopie", "-no-pie")
    if non_pie is None:
        pytest.skip("toolchain cannot link -no-pie — skip != pass")
    readelf_base = _readelf_lowest_load(readelf, non_pie)
    assert (
        readelf_base is not None and readelf_base > 0
    ), "readelf found no fixed-base LOAD in a -no-pie build"
    arch, base = elf_preferred_base(non_pie)
    # The exact independent-oracle check: our hand parse of the lowest load
    # vaddr must equal what readelf's own parser reports, to the byte.
    assert base == readelf_base, f"our base {base!r} != readelf lowest LOAD {readelf_base:#x}"
    # The machine byte must decode to a real arch too (the runner is x86-64);
    # a mis-decoded e_machine would drop the tag or invent the wrong one.
    assert arch in (Architecture.X64, Architecture.X86), arch

    # A PIE reads back as va-only: its first LOAD is at vaddr 0, so there is no
    # fixed base to invent. readelf confirms the 0, then our parser must say None.
    pie = _build("base_pie", "-pie", "-fPIE")
    if pie is not None and _readelf_lowest_load(readelf, pie) == 0:
        _, pie_base = elf_preferred_base(pie)
        assert pie_base is None, f"a PIE (LOAD at vaddr 0) must be va-only, got {pie_base!r}"
