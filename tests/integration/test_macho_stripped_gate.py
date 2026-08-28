"""Cross-validate the Mach-O ``stripped`` fact against llvm-nm.

A native session over a Mach-O now reports whether the local symbols ``strip``
removes are gone -- the debug-map STABS a ``-g`` build carries and the local
defined symbols -- leaving an all-external table. This is the Mach-O pair to
the ELF ``stripped`` fact, and the nlist-flag decode (which entries are local)
is ours, so llvm-nm referees it: ``llvm-nm --format=posix`` prints each
symbol with a type letter that is lowercase for a local symbol and uppercase
for an external one, so "has a local symbol" is a verdict an independent tool
renders over the same table. The session's ``stripped`` must be the negation
of "llvm-nm shows a local symbol" over an image carrying a local symbol, over
one carrying only externals, and over the committed real-world fixture.

llvm-nm comes from the workflow's ``llvm`` install. skip != pass: the gate
skips, naming the missing piece, only when llvm-nm or the fixture is absent.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

# Mach-O nlist n_type bits: N_EXT marks an external symbol; the low nibble is
# N_SECT (0x0e) for one defined in a section here. N_SO (0x64) is a STABS
# debug-map entry -- a -g source-file marker, N_STAB set.
_N_EXT, _N_SECT, _N_UNDF, _N_SO = 0x01, 0x0E, 0x00, 0x64


def _macho_exec_with_symbols(symbols: list[tuple[str, int, int]]) -> bytes:
    """A minimal MH_EXECUTE arm64 Mach-O carrying an LC_SYMTAB of the given nlist.

    Each symbol is ``(name, n_type, n_sect)``. Built here independently of the
    reader; llvm-nm's strict Mach-O decode doubles as the well-formedness
    check.
    """
    strtab = bytearray(b"\x00")
    nlists = bytearray()
    for name, n_type, n_sect in symbols:
        strx = len(strtab)
        strtab += name.encode() + b"\x00"
        nlists += struct.pack("<IBBHQ", strx, n_type, n_sect, 0, 0)
    symoff = 32 + 24
    stroff = symoff + len(nlists)
    cmd = struct.pack("<IIIIII", 0x02, 24, symoff, len(symbols), stroff, len(strtab))
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(cmd), 0, 0)
    return header + cmd + bytes(nlists) + bytes(strtab)


def _session_stripped(binary: Path) -> bool:
    service = AnalysisService()
    try:
        created = service.create_session(str(binary))
        assert created.ok, created.error
        return bool(created.data["session"]["metadata"]["native"]["stripped"])
    finally:
        service.close_all()


def _llvm_nm_has_local(nm: str, binary: Path) -> bool:
    """True when llvm-nm prints a symbol ``strip`` would remove.

    ``-a --format=posix`` prints ``name type value size`` per line, including
    the debugger-only STABS entries (``-a``). The type letter is lowercase for
    a local symbol, ``-`` for a debug (STABS) symbol, and uppercase for an
    external one (``u``/``v``/``w`` are weak/undefined externals, not locals).
    A local or debug symbol is exactly what stripping takes.
    """
    result = subprocess.run(
        [nm, "-a", "--format=posix", str(binary)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[1]) == 1:
            letter = parts[1]
            if letter == "-" or (letter.islower() and letter not in "uvw"):
                return True
    return False


@pytest.mark.integration
def test_a_local_bearing_image_reads_unstripped_like_llvm_nm(tmp_path: Path) -> None:
    nm = shutil.which("llvm-nm")
    if nm is None:
        pytest.skip("llvm-nm not installed — Mach-O stripped gate not run (skip != pass)")

    binary = tmp_path / "unstripped.macho"
    binary.write_bytes(
        _macho_exec_with_symbols(
            [
                ("_main", _N_SECT | _N_EXT, 1),  # external: survives strip
                ("_puts", _N_UNDF | _N_EXT, 0),  # undefined external: survives
                ("_helper", _N_SECT, 1),  # local defined: strip's target
            ]
        )
    )
    # llvm-nm sees a local symbol, so the census must read not-stripped.
    assert _llvm_nm_has_local(nm, binary) is True
    assert _session_stripped(binary) is False


@pytest.mark.integration
def test_a_stab_bearing_image_reads_unstripped_like_llvm_nm(tmp_path: Path) -> None:
    nm = shutil.which("llvm-nm")
    if nm is None:
        pytest.skip("llvm-nm not installed — Mach-O stripped gate not run (skip != pass)")

    binary = tmp_path / "debug.macho"
    binary.write_bytes(
        _macho_exec_with_symbols([("_main", _N_SECT | _N_EXT, 1), ("probe.c", _N_SO, 0)])
    )
    assert _llvm_nm_has_local(nm, binary) is True
    assert _session_stripped(binary) is False


@pytest.mark.integration
def test_an_all_external_image_reads_stripped_like_llvm_nm(tmp_path: Path) -> None:
    nm = shutil.which("llvm-nm")
    if nm is None:
        pytest.skip("llvm-nm not installed — Mach-O stripped gate not run (skip != pass)")

    binary = tmp_path / "stripped.macho"
    binary.write_bytes(
        _macho_exec_with_symbols(
            [("_main", _N_SECT | _N_EXT, 1), ("_puts", _N_UNDF | _N_EXT, 0)]
        )
    )
    # No local symbol on either side: stripped is the shared answer.
    assert _llvm_nm_has_local(nm, binary) is False
    assert _session_stripped(binary) is True


@pytest.mark.integration
def test_the_committed_fixture_agrees_with_llvm_nm() -> None:
    nm = shutil.which("llvm-nm")
    if nm is None:
        pytest.skip("llvm-nm not installed — Mach-O stripped gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"Mach-O fixture missing: {_MACHO_FIXTURE} (skip != pass)")

    # A real committed image: the census and llvm-nm must reach the same
    # stripped verdict over it, whatever that verdict is.
    assert _session_stripped(_MACHO_FIXTURE) == (not _llvm_nm_has_local(nm, _MACHO_FIXTURE))
