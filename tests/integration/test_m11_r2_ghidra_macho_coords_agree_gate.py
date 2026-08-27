"""M11 cross-engine gate: r2 and Ghidra agree on Mach-O coordinates.

Mach-O became a first-class session target, and both backends learned to derive
its load base and architecture from the header -- r2 via ``enrich_r2_payload``,
Ghidra via ``enrich_ghidra_payload``, both sharing ``preferred_base``. Every
existing agree/e2e gate is ELF or PE, so nothing exercised that convergence on a
real Mach-O through the running engines. This gate closes that gap for a thin
x86_64 image (base 0x100000000) and a thin arm64 image (base 0x140000000): one
Mach-O session driven through the AnalysisService must have both engines

* accept the Mach-O and return a well-formed functions export (no loader
  error),
* report the identical top-level frame -- module, image_base, architecture --
  matching the base the header declares and the architecture the session was
  classified with, and
* recover a function at the ``LC_MAIN`` entry and attach the *same* coordinate
  object there (r2's ``address`` vs Ghidra's ``entry_address``), byte for byte.

The fixtures are hand-built (no toolchain emits Mach-O here): a single-byte-ish
``__text`` with an ``LC_MAIN`` entry, enough that both engines create exactly
one function at a known VA. The two engines name it differently (r2 ``main``
from LC_MAIN, Ghidra ``entry``), which is precisely why the gate joins on the
coordinate object rather than the name. skip != pass when radare2/rizin or
Ghidra is missing.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_COORD_KEYS = {"module", "rva", "va", "architecture"}
_CODE_OFF = 0x400
# (cputype, cpusubtype, arch label, __TEXT base, entry code) per fixture. The
# code is a minimal valid function body for the ISA (an x86_64 prologue+ret, an
# arm64 ret) so each engine's analysis settles on one function at the entry.
_X64 = (0x01000007, 3, "x64", 0x100000000, b"\x55\x48\x89\xe5\x5d\xc3")
_ARM64 = (0x0100000C, 0, "arm64", 0x140000000, b"\xc0\x03\x5f\xd6")


def _segment(
    name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int,
    maxprot: int, initprot: int, sects: bytes = b"",
) -> bytes:
    nsects = 1 if sects else 0
    body = struct.pack("<II", 0x19, 72 + len(sects)) + name.encode().ljust(16, b"\x00")
    body += struct.pack("<QQQQ", vmaddr, vmsize, fileoff, filesize)
    body += struct.pack("<iiII", maxprot, initprot, nsects, 0)
    return body + sects


def _text_section(addr: int, size: int, offset: int) -> bytes:
    body = b"__text".ljust(16, b"\x00") + b"__TEXT".ljust(16, b"\x00")
    body += struct.pack("<QQ", addr, size)
    # offset, align, reloff, nreloc, flags (PURE|SOME_INSTRUCTIONS), reserved1..3
    body += struct.pack("<IIIIIIII", offset, 0, 0, 0, 0x80000400, 0, 0, 0)
    return body


def _write_macho_with_entry(
    path: Path, *, cputype: int, cpusubtype: int, text_base: int, code: bytes
) -> int:
    """A thin 64-bit MH_EXECUTE with __PAGEZERO, __TEXT+__text, and LC_MAIN.

    Returns the entry virtual address (``text_base + _CODE_OFF``). LC_MAIN's
    ``entryoff`` is a file offset, which maps to that VA because __TEXT loads at
    fileoff 0. The whole thing is arch-agnostic beyond the cputype and the code
    bytes, so both engines find one function there.
    """
    sect = _text_section(text_base + _CODE_OFF, len(code), _CODE_OFF)
    cmds = _segment("__PAGEZERO", 0, text_base, 0, 0, 0, 0)
    cmds += _segment("__TEXT", text_base, 0x1000, 0, 0x1000, 5, 5, sect)
    cmds += struct.pack("<IIQQ", 0x80000028, 24, _CODE_OFF, 0)  # LC_MAIN
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIII", cputype, cpusubtype, 2, 3, len(cmds))
    header += struct.pack("<II", 0, 0)  # flags + reserved
    image = bytearray((header + cmds).ljust(0x1000, b"\x00"))
    image[_CODE_OFF : _CODE_OFF + len(code)] = code
    path.write_bytes(bytes(image))
    return text_base + _CODE_OFF


def _coord(value: object) -> dict[str, Any]:
    assert isinstance(value, dict), value
    assert set(value) == _COORD_KEYS, value
    return value


def _frame(payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (payload.get("module"), payload.get("image_base"), payload.get("architecture"))


def _entry_coord(items: list[Any], object_field: str, entry_va: int) -> dict[str, Any] | None:
    """The coordinate object of the recovered function that sits at ``entry_va``."""
    for item in items:
        if not isinstance(item, dict):
            continue
        obj = item.get(object_field)
        if isinstance(obj, dict) and obj.get("va") == entry_va:
            return _coord(obj)
    return None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("cputype", "cpusubtype", "arch", "text_base", "code"),
    [_X64, _ARM64],
    ids=["x86_64", "arm64"],
)
def test_m11_r2_and_ghidra_agree_on_macho_coordinates(
    tmp_path: Path, cputype: int, cpusubtype: int, arch: str, text_base: int, code: bytes
) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — Mach-O coords Gate not run (skip != pass)")
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")

    binary = tmp_path / f"{arch}.macho"
    entry_va = _write_macho_with_entry(
        binary, cputype=cputype, cpusubtype=cpusubtype, text_base=text_base, code=code
    )

    service = AnalysisService(Settings.load())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    # The regression this guards: a Mach-O now creates a session and is
    # classified with the architecture its header names, not routed to the PE
    # machine probe that used to reject it.
    assert session["target"] == "macho", session
    assert session["architecture"] == arch, session
    sid = str(session["id"])

    r2_funcs = service.r2_functions(sid, timeout=60.0)
    assert r2_funcs.ok and r2_funcs.data is not None, r2_funcs.error
    assert r2_funcs.data.get("parsed") is True, r2_funcs.data

    gh_funcs = service.ghidra_functions(sid, limit=64, timeout=300.0)
    assert gh_funcs.ok and gh_funcs.data is not None, gh_funcs.error
    assert gh_funcs.data.get("mode") == "functions", gh_funcs.data

    # Agreement 1: one coordinate frame, equal to the header base and the
    # session architecture, from both engines.
    expected_frame = (binary.name, text_base, arch)
    assert _frame(r2_funcs.data) == expected_frame, r2_funcs.data
    assert _frame(gh_funcs.data) == expected_frame, gh_funcs.data

    # Agreement 2: both recover a function at the LC_MAIN entry, and the
    # coordinate object each attaches there is identical field for field.
    expected_coord = {
        "module": binary.name,
        "rva": _CODE_OFF,
        "va": entry_va,
        "architecture": arch,
    }
    r2_entry = _entry_coord(r2_funcs.data.get("items", []), "address", entry_va)
    gh_entry = _entry_coord(gh_funcs.data.get("items", []), "entry_address", entry_va)
    assert r2_entry == expected_coord, r2_funcs.data.get("items")
    assert gh_entry == expected_coord, gh_funcs.data.get("items")
    assert r2_entry == gh_entry
