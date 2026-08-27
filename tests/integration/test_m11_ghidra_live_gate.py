"""M11 Ghidra live gate: headless analyze + export against a committed PE.

Ghidra's analyzeHeadless backend is portable, so it analyses a PE the same way
on Linux as on Windows -- through the Jython script provider on Ghidra <= 11.2
and through PyGhidra on >= 11.3. This gate drives the real launcher end to end:
it imports a PE, lists functions with their entry addresses, and decompiles one
of them. skip != pass: it skips only when HEADLESS_RE_GHIDRA_HOME is unset or the
install is not runnable here (no java, or PyGhidra without its Python package).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# analyzeHeadless imports and auto-analyses the whole PE before the export
# script runs, and each export re-imports; give it real headroom on a slow box.
_TIMEOUT = 480.0


def _ghidra_home() -> Path | None:
    raw = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not raw:
        return None
    home = Path(raw).expanduser()
    return home if home.is_dir() else None


def _pe_fixture() -> Path | None:
    """A PE for Ghidra to import, preferring the Windows-built gate fixture."""
    primary = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if primary.is_file():
        return primary
    committed = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
    return committed if committed.is_file() else None


@pytest.mark.integration
def test_m11_ghidra_live_functions_and_decompile(tmp_path: Path) -> None:
    home = _ghidra_home()
    if home is None:
        pytest.skip("HEADLESS_RE_GHIDRA_HOME unset — live Gate not run (skip≠pass)")
    client = GhidraClient(home=home)
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
