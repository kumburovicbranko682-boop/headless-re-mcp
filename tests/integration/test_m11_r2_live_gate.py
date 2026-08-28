"""M11 r2 live gate: address mapping, disassembly, xrefs. skip≠pass when r2 missing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

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
    source.write_text("int helper(int x){return x+1;}\nint main(void){return helper(41);}\n")
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
