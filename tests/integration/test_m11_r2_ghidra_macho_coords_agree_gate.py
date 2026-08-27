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
  classified with,
* recover the *same two functions* (an ``LC_MAIN`` entry that calls a callee)
  and attach the same coordinate object at each, byte for byte, and
* resolve the entry -> callee call and report the same ``from_address``
  coordinate for that site (r2's ``axtj`` vs Ghidra's inbound references).

The fixtures are hand-built (no toolchain emits Mach-O here): a two-function
``__text`` (entry does ``call``/``bl`` into a callee, both ``ret``) with an
``LC_MAIN`` entry, enough that both engines create exactly those two functions
and the edge between them. The engines name and type things differently (r2
``main``/``CALL``, Ghidra ``entry``/``UNCONDITIONAL_CALL``), which is precisely
why the gate joins on the coordinate object rather than the name or type.
skip != pass when radare2/rizin or Ghidra is missing.
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
_ENTRY_OFF = 0x400  # entry function (and its call site) within __TEXT
_CALLEE_OFF = 0x410  # callee, 0x10 past the entry


def _entry_code(arch: str) -> bytes:
    """Two functions in one blob: entry at 0x0 calls the callee at 0x10.

    x86_64: ``call rel32; ret`` then ``ret`` (rel32 reaches 0x10 from the
    instruction after the 5-byte call). arm64: ``bl #0x10; ret`` then ``ret``
    (bl's imm is (0x10)/4 = 4). Both are minimal valid bodies the analyzers
    settle on as exactly two functions.
    """
    blob = bytearray(_CALLEE_OFF - _ENTRY_OFF + 4)
    if arch == "x64":
        blob[0:6] = b"\xe8\x0b\x00\x00\x00\xc3"  # call 0x100000410 ; ret
        blob[0x10] = 0xC3  # callee: ret
    else:
        blob[0:8] = b"\x04\x00\x00\x94\xc0\x03\x5f\xd6"  # bl 0x140000410 ; ret
        blob[0x10:0x14] = b"\xc0\x03\x5f\xd6"  # callee: ret
    return bytes(blob)


# (cputype, cpusubtype, arch label, __TEXT base) per fixture.
_X64 = (0x01000007, 3, "x64", 0x100000000)
_ARM64 = (0x0100000C, 0, "arm64", 0x140000000)


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


def _write_macho(path: Path, *, cputype: int, cpusubtype: int, text_base: int, code: bytes) -> None:
    """A thin 64-bit MH_EXECUTE with __PAGEZERO, __TEXT+__text, and LC_MAIN.

    LC_MAIN's ``entryoff`` is a file offset that maps to ``text_base+_ENTRY_OFF``
    because __TEXT loads at fileoff 0. The code sits at that same offset.
    """
    sect = _text_section(text_base + _ENTRY_OFF, len(code), _ENTRY_OFF)
    cmds = _segment("__PAGEZERO", 0, text_base, 0, 0, 0, 0)
    cmds += _segment("__TEXT", text_base, 0x1000, 0, 0x1000, 5, 5, sect)
    cmds += struct.pack("<IIQQ", 0x80000028, 24, _ENTRY_OFF, 0)  # LC_MAIN
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIII", cputype, cpusubtype, 2, 3, len(cmds))
    header += struct.pack("<II", 0, 0)  # flags + reserved
    image = bytearray((header + cmds).ljust(0x1000, b"\x00"))
    image[_ENTRY_OFF : _ENTRY_OFF + len(code)] = code
    path.write_bytes(bytes(image))


def _coord(value: object) -> dict[str, Any]:
    assert isinstance(value, dict), value
    assert set(value) == _COORD_KEYS, value
    return value


def _frame(payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (payload.get("module"), payload.get("image_base"), payload.get("architecture"))


def _coord_at(items: list[Any], object_field: str, va: int) -> dict[str, Any] | None:
    """The coordinate object of the item whose ``object_field`` sits at ``va``."""
    for item in items:
        if not isinstance(item, dict):
            continue
        obj = item.get(object_field)
        if isinstance(obj, dict) and obj.get("va") == va:
            return _coord(obj)
    return None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("cputype", "cpusubtype", "arch", "text_base"),
    [_X64, _ARM64],
    ids=["x86_64", "arm64"],
)
def test_m11_r2_and_ghidra_agree_on_macho_coordinates(
    tmp_path: Path, cputype: int, cpusubtype: int, arch: str, text_base: int
) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — Mach-O coords Gate not run (skip != pass)")
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")

    binary = tmp_path / f"{arch}.macho"
    _write_macho(
        binary, cputype=cputype, cpusubtype=cpusubtype, text_base=text_base, code=_entry_code(arch)
    )
    entry_va = text_base + _ENTRY_OFF
    callee_va = text_base + _CALLEE_OFF

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

    # Agreement 2: both recover the entry and the callee, and the coordinate
    # object each attaches is identical field for field.
    r2_items = r2_funcs.data.get("items", [])
    gh_items = gh_funcs.data.get("items", [])
    for va, off in ((entry_va, _ENTRY_OFF), (callee_va, _CALLEE_OFF)):
        expected = {"module": binary.name, "rva": off, "va": va, "architecture": arch}
        r2_c = _coord_at(r2_items, "address", va)
        gh_c = _coord_at(gh_items, "entry_address", va)
        assert r2_c == expected, (va, r2_items)
        assert gh_c == expected, (va, gh_items)
        assert r2_c == gh_c

    # Agreement 3: the entry -> callee call site. r2's axtj and Ghidra's inbound
    # references both point at the callee from the same site; the from_address
    # coordinate object is identical (the call is the entry's first instruction,
    # so it lands on the entry coordinate).
    expected_site = {"module": binary.name, "rva": _ENTRY_OFF, "va": entry_va, "architecture": arch}
    r2_xrefs = service.r2_xrefs_to(sid, callee_va, timeout=60.0)
    assert r2_xrefs.ok and r2_xrefs.data is not None, r2_xrefs.error
    r2_calls = [
        _coord(i.get("from_address"))
        for i in r2_xrefs.data.get("items", [])
        if "CALL" in str(i.get("type"))
    ]
    assert expected_site in r2_calls, r2_xrefs.data.get("items")

    gh_xrefs = service.ghidra_xrefs(sid, hex(callee_va), limit=64, timeout=300.0)
    assert gh_xrefs.ok and gh_xrefs.data is not None, gh_xrefs.error
    gh_calls = [
        _coord(i.get("from_address"))
        for i in gh_xrefs.data.get("items", [])
        if "CALL" in str(i.get("type"))
    ]
    assert expected_site in gh_calls, gh_xrefs.data.get("items")
