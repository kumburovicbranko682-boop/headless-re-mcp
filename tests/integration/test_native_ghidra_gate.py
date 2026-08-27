"""Native (ELF) line, end to end through Ghidra. skip != pass when Ghidra missing.

The r2 native gate proves one cross-platform backend over a Linux binary; this
proves the other. An ELF opens as a NATIVE session and Ghidra headless analysis
runs the real export surface against it -- functions, symbols, and a decompile
of a real function to C. It needs a JDK, the Ghidra distribution
(HEADLESS_RE_GHIDRA_HOME), and a system ELF, all present on the Linux CI lane,
so it runs there rather than skipping.
"""

from __future__ import annotations

import glob
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"


def _system_elf() -> Path | None:
    for candidate in ["/bin/ls", "/usr/bin/ls", "/usr/bin/python3"]:
        path = Path(candidate)
        if path.is_file():
            return path.resolve()
    libc = next((p for p in glob.glob("/lib/*/libc.so.6") if Path(p).is_file()), None)
    return Path(libc).resolve() if libc else None


@pytest.mark.integration
def test_native_elf_analyzes_through_ghidra() -> None:
    settings = Settings.load()
    if not GhidraClient(home=settings.ghidra_home).available:
        pytest.skip("Ghidra/JDK not configured — native ghidra gate not run (skip != pass)")
    elf = _system_elf()
    if elf is None:
        pytest.skip("no system ELF available — native ghidra gate not run (skip != pass)")

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(elf))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "native"
        assert session["metadata"]["native"]["format"] == "elf"
        session_id = str(session["id"])

        functions = service.ghidra_functions(session_id, limit=64, timeout=240.0)
        assert functions.ok, functions.error
        assert functions.data["count"] >= 1
        rows = cast(list[dict[str, Any]], functions.data["items"])
        first = rows[0]
        assert str(first.get("name") or "").strip()
        entry = str(first["entry"]).strip()
        assert entry  # a Ghidra address string for the function entry

        symbols = service.ghidra_symbols(session_id, limit=64, timeout=240.0)
        assert symbols.ok, symbols.error
        assert symbols.data["count"] >= 1
        sym_rows = cast(list[dict[str, Any]], symbols.data["items"])
        assert any(str(row.get("name") or "").strip() for row in sym_rows)

        # Decompiling the first function must land on that function and produce
        # real C text, proving analysis (not just header parsing) ran.
        decompiled = service.ghidra_decompile(session_id, int(entry, 16), timeout=240.0)
        assert decompiled.ok, decompiled.error
        assert decompiled.data["found"] is True
        assert str(decompiled.data.get("decompiled") or "").strip()
    finally:
        service.close_all()


@pytest.mark.integration
def test_native_macho_analyzes_through_ghidra() -> None:
    """The macOS half, proven on Linux: Ghidra imports and decompiles a Mach-O.

    The r2 gate proves radare2 over both native formats; the ELF case above
    proves Ghidra over ELF. This closes the last quadrant -- Ghidra over Mach-O
    -- using the same committed, hand-built fixture the r2 gate uses, so a Linux
    runner with no macOS binary still exercises the whole Mach-O path: classify,
    open as NATIVE, then Ghidra analysis, functions and a decompile to C.
    """
    settings = Settings.load()
    if not GhidraClient(home=settings.ghidra_home).available:
        pytest.skip("Ghidra/JDK not configured — native ghidra gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")

    service = AnalysisService(settings)
    try:
        created = service.create_session(str(_MACHO_FIXTURE))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "native"
        assert session["metadata"]["native"]["format"] == "macho"
        session_id = str(session["id"])

        functions = service.ghidra_functions(session_id, limit=64, timeout=240.0)
        assert functions.ok, functions.error
        assert functions.data["count"] >= 1
        rows = cast(list[dict[str, Any]], functions.data["items"])
        first = rows[0]
        assert str(first.get("name") or "").strip()
        entry = str(first["entry"]).strip()
        assert entry

        symbols = service.ghidra_symbols(session_id, limit=64, timeout=240.0)
        assert symbols.ok, symbols.error
        assert symbols.data["count"] >= 1

        # The entry body (xor eax,eax; ret) must decompile to real C, proving
        # Ghidra analysis -- not just Mach-O header parsing -- ran on our bytes.
        decompiled = service.ghidra_decompile(session_id, int(entry, 16), timeout=240.0)
        assert decompiled.ok, decompiled.error
        assert decompiled.data["found"] is True
        assert str(decompiled.data.get("decompiled") or "").strip()
    finally:
        service.close_all()
