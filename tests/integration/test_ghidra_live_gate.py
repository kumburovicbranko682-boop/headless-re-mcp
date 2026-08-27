"""Ghidra live gate: real analyzeHeadless functions/symbols/decompile on an ELF.

The unit tests mock analyzeHeadless, so nothing proved the backend actually
drives a real Ghidra -- and it did not: discovery returned the Windows
launcher on Linux, and the Jython postScript died on every Ghidra 11.3+. This
gate runs the real thing against the portable ELF fixture and asserts the
export shape the client and tools catalog promise. skip != pass: it skips only
when Ghidra (and a JDK) are genuinely absent, naming what is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings


def _ghidra_or_skip() -> GhidraClient:
    try:
        home = Settings.load().ghidra_home
    except Exception:  # noqa: BLE001 - a bad config is not a reason to error the gate
        home = None
    client = GhidraClient(home=home)
    if not client.available:
        pytest.skip(
            "Ghidra analyzeHeadless / JDK not configured "
            "(set HEADLESS_RE_GHIDRA_HOME) — live Gate not run (skip != pass)"
        )
    return client


def _entry_of(items: list[dict], name: str) -> str | None:
    for item in items:
        if item.get("name") == name:
            entry = item.get("entry")
            return str(entry) if entry is not None else None
    return None


@pytest.mark.integration
def test_ghidra_live_functions_and_symbols_on_elf(
    elf_fixture: Path, tmp_path: Path
) -> None:
    """Real analyzeHeadless recovers the ELF's named functions and symbols.

    The fixture is compiled unstripped, so Ghidra reads elf_fixture_transform
    and main from the symbol table -- their presence proves this is a genuine
    analysis, not an empty envelope that happens to parse.
    """
    client = _ghidra_or_skip()

    funcs = client.functions(elf_fixture, tmp_path / "fn", limit=512, timeout=600.0)
    assert funcs.get("count", 0) >= 2
    items = funcs["items"]
    assert items and all({"name", "entry", "body_size"} <= set(item) for item in items)
    names = {item["name"] for item in items}
    assert {"elf_fixture_transform", "main"} <= names
    transform = next(item for item in items if item["name"] == "elf_fixture_transform")
    assert int(transform["body_size"]) > 0

    symbols = client.symbols(elf_fixture, tmp_path / "sym", limit=1024, timeout=600.0)
    assert symbols.get("count", 0) >= 1
    sym_items = symbols["items"]
    assert all({"name", "address", "type"} <= set(item) for item in sym_items)
    assert "elf_fixture_transform" in {item["name"] for item in sym_items}


@pytest.mark.integration
def test_ghidra_live_decompiles_the_named_helper(
    elf_fixture: Path, tmp_path: Path
) -> None:
    """The decompiler returns real C for the function at a discovered address."""
    client = _ghidra_or_skip()

    funcs = client.functions(elf_fixture, tmp_path / "fn", limit=512, timeout=600.0)
    entry = _entry_of(funcs["items"], "elf_fixture_transform")
    assert entry is not None, "elf_fixture_transform was not among the functions"

    decompiled = client.decompile(elf_fixture, tmp_path / "dec", entry, timeout=600.0)
    assert decompiled.get("function") == "elf_fixture_transform"
    assert decompiled.get("truncated") is False
    body = decompiled.get("decompiled") or ""
    assert isinstance(body, str) and body.strip()
    assert "elf_fixture_transform" in body
