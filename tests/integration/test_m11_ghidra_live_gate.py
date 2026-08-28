"""M11 Ghidra live gate: headless analyze + export against a committed PE.

Ghidra's analyzeHeadless backend is portable, so it analyses a PE the same way
on Linux as on Windows -- through the Jython script provider on Ghidra <= 11.2
and through PyGhidra on >= 11.3. These gates drive the real launcher end to
end across all four export modes: the PE test lists functions, pages symbols
and decompiles; the ELF test compiles a two-function fixture and resolves the
cross-references to a callee, so the one ExportJson.py mode with no other live
coverage (xrefs) runs against the real interpreter too. skip != pass: they
skip only when HEADLESS_RE_GHIDRA_HOME is unset or names a missing directory,
or the install is not runnable here (no java, or PyGhidra without its Python
package) -- and the skip message says which.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# analyzeHeadless imports and auto-analyses the whole PE before the export
# script runs, and each export re-imports; give it real headroom on a slow box.
_TIMEOUT = 480.0


def _ghidra_home() -> Path:
    """The configured Ghidra home, or a skip that names what is actually wrong.

    Folding "not set" and "set but not a directory" into one None made the skip
    say "unset" when the variable was set and the install had merely vanished --
    exactly the half-failed-download case the CI step can produce, and a reader
    chasing that message checks the workflow env instead of the filesystem.
    """
    raw = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not raw:
        pytest.skip("HEADLESS_RE_GHIDRA_HOME unset — live Gate not run (skip≠pass)")
    home = Path(raw).expanduser()
    if not home.is_dir():
        pytest.skip(
            f"HEADLESS_RE_GHIDRA_HOME={raw!r} is not a directory — live Gate not run (skip≠pass)"
        )
    return home


def _pe_fixture() -> Path | None:
    """A PE for Ghidra to import, preferring the Windows-built gate fixture."""
    primary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if primary.is_file():
        return primary
    committed = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
    return committed if committed.is_file() else None


@pytest.mark.integration
def test_m11_ghidra_live_functions_and_decompile(tmp_path: Path) -> None:
    client = GhidraClient(home=_ghidra_home())
    if not client.available:
        pytest.skip(
            "Ghidra install not runnable here (no java, or PyGhidra without its "
            "python package) — live Gate not run (skip≠pass)"
        )
    fixture = _pe_fixture()
    if fixture is None:
        pytest.skip("no PE fixture available for Ghidra — live Gate not run (skip≠pass)")

    functions = client.functions(fixture, tmp_path / "funcs", limit=32, timeout=_TIMEOUT)
    assert functions.get("mode") == "functions"
    items = functions.get("items") or []
    assert functions.get("count", 0) >= 1
    assert items, "ghidra returned no functions"
    first = items[0]
    assert isinstance(first.get("name"), str) and first["name"]
    assert isinstance(first.get("entry"), str) and first["entry"]

    # symbols had no live coverage at all: nothing proved the mode string
    # reaches the script, that a modern SymbolTable still yields name/address/
    # type as strings, or that the limit paginates. A real PE carries dozens of
    # import symbols alone, so limit=16 must fill the page and set has_more --
    # measured against Ghidra 12.1.3, which reports external imports at
    # addresses like "EXTERNAL:00000001", hence no hex assertion on address.
    symbols = client.symbols(fixture, tmp_path / "syms", limit=16, timeout=_TIMEOUT)
    assert symbols.get("mode") == "symbols"
    sym_items = symbols.get("items") or []
    assert symbols.get("count") == 16 and len(sym_items) == 16
    assert symbols.get("has_more") is True, "a 16-symbol page of a real PE must paginate"
    for sym in sym_items:
        assert isinstance(sym.get("name"), str) and sym["name"]
        assert isinstance(sym.get("address"), str) and sym["address"]
        assert isinstance(sym.get("type"), str) and sym["type"]

    # Pick a function with a real body so the decompiler has something to emit.
    target = next(
        (item for item in items if int(item.get("body_size", 0) or 0) > 16),
        first,
    )
    entry = target["entry"]
    address = entry if entry.lower().startswith("0x") else f"0x{entry}"
    decompiled = client.decompile(fixture, tmp_path / "dec", address, timeout=_TIMEOUT)
    assert decompiled.get("mode") == "decompile"
    assert isinstance(decompiled.get("decompiled"), str)
    assert decompiled["decompiled"].strip(), "ghidra produced empty decompilation"


@pytest.mark.integration
def test_m11_ghidra_live_elf_functions_and_xrefs(tmp_path: Path) -> None:
    """Ghidra resolves an ELF's functions and the xrefs to a known callee.

    Two gaps close here. First, xrefs was the one ExportJson.py mode no live
    gate exercised, so an API drift in getReferencesTo -- the Ghidra twin of
    the r2 key renames this suite already caught -- would have shipped silently.
    Second, ELF is now a first-class session target whose portable backends are
    r2 and Ghidra, and only r2 had an ELF gate. A compiled two-function fixture
    makes the assertion deterministic: main calls greet, so the references to
    greet's entry must include a CALL whose source lies inside main's body.
    Measured against Ghidra 12.1.3, the same query also returns rows whose
    `from` is not an address at all ("Entry Point", type EXTERNAL), so the gate
    only requires hex of the row it hunts for, and pins `to` on every row.
    """
    client = GhidraClient(home=_ghidra_home())
    if not client.available:
        pytest.skip(
            "Ghidra install not runnable here (no java, or PyGhidra without its "
            "python package) — live Gate not run (skip≠pass)"
        )
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler to build an ELF fixture — live Gate not run (skip≠pass)")

    source = tmp_path / "elf_fixture.c"
    source.write_text(
        "int greet(int value) { return value + 1; }\nint main(void) { return greet(41); }\n"
    )
    fixture = tmp_path / "elf_fixture"
    build = subprocess.run(
        [gcc, "-no-pie", "-O0", "-o", str(fixture), str(source)],
        capture_output=True,
        text=True,
        timeout=120.0,
    )
    if build.returncode != 0 or not fixture.is_file():
        # -no-pie can be unsupported on a hardened toolchain (some distros
        # build gcc PIE-only). That is a toolchain limitation, not a Ghidra
        # regression, so skip rather than fail.
        pytest.skip(f"could not build a non-PIE ELF ({build.stderr.strip()[:200]}) — skip≠pass")

    functions = client.functions(fixture, tmp_path / "funcs", limit=64, timeout=_TIMEOUT)
    assert functions.get("mode") == "functions"
    by_name = {
        item.get("name"): item
        for item in functions.get("items") or []
        if isinstance(item.get("name"), str)
    }
    assert "greet" in by_name and "main" in by_name, sorted(by_name)
    greet_entry = int(by_name["greet"]["entry"], 16)
    main_entry = int(by_name["main"]["entry"], 16)
    main_end = main_entry + int(by_name["main"]["body_size"])

    xrefs = client.xrefs(fixture, tmp_path / "xrefs", hex(greet_entry), limit=64, timeout=_TIMEOUT)
    assert xrefs.get("mode") == "xrefs"
    rows = xrefs.get("items") or []
    assert xrefs.get("count", 0) >= 1 and rows, "no references to a function main calls"
    for row in rows:
        assert isinstance(row.get("type"), str) and row["type"]
        assert int(row["to"], 16) == greet_entry, f"a ref to a different address: {row}"

    def _from_va(row: dict[str, object]) -> int | None:
        try:
            return int(str(row.get("from")), 16)
        except ValueError:
            return None  # e.g. Ghidra's synthetic "Entry Point" row

    calls = [
        row
        for row in rows
        if "CALL" in row["type"]
        and (va := _from_va(row)) is not None
        and main_entry <= va < main_end
    ]
    assert calls, f"no CALL to greet from inside main among {rows}"
