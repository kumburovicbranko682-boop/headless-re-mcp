"""M11 cross-engine gate: r2 and Ghidra agree on Mach-O data references.

The Mach-O coords gate pins agreement on the *call* edge (code -> code); the
data-xref agree gates that prove code -> *data* convergence are all ELF, ARM or
PE, so nothing exercised it on a Mach-O. This closes that gap for a thin
x86_64 image: two functions each load the address of one ``__data`` datum with
a RIP-relative ``lea``, and one session driven through the AnalysisService must
have both engines

* recover the two functions (an ``LC_MAIN`` entry that calls a callee), and
* report a data reference to that datum from *exactly* the two ``lea`` sites,
  with the ``from_address`` coordinate object identical field for field between
  the engines and equal to the two function entries (the ``lea`` is each
  function's first instruction), and
* agree the reference targets the same datum (the ``to_address`` coordinate).

Like the ELF data-xref gate this is x86_64 only: the arm64 data reference is an
``adrp``+``add`` pair that neither engine resolves under the default headless
analysis these tools run (verified: both create the two functions but form no
reference), so arm64 code->data stays covered by the ARM ELF gate, which feeds
both engines a real compiler's code. The fixture is hand-built because no
toolchain emits Mach-O here. skip != pass when radare2/rizin or Ghidra is
missing.
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
_TEXT_BASE = 0x100000000
_ENTRY_OFF = 0x400
_CALLEE_OFF = 0x420
_DATA_OFF = 0x1008  # inside __DATA, deliberately not page-aligned
_ARCH = "x64"
# Ghidra types a plain address load DATA and a call-argument address PARAM;
# both are data references, never control flow.
_DATA_KINDS = {"DATA", "PARAM"}


def _text_code() -> bytes:
    """entry (lea+call+ret) and callee (lea+ret); both leas read __data+0x1008.

    RIP-relative ``lea rax,[rip+disp]`` where disp reaches the datum from the
    address after the 7-byte instruction: entry's lea is at _ENTRY_OFF, callee's
    at _CALLEE_OFF, so the two disps differ but both resolve to _DATA_OFF.
    """
    blob = bytearray(_CALLEE_OFF - _ENTRY_OFF + 8)
    entry_disp = _DATA_OFF - (_ENTRY_OFF + 7)
    callee_disp = _DATA_OFF - (_CALLEE_OFF + 7)
    blob[0:3] = b"\x48\x8d\x05"
    blob[3:7] = struct.pack("<i", entry_disp)  # lea rax,[rip+entry_disp]
    blob[7:12] = b"\xe8" + struct.pack("<i", _CALLEE_OFF - (_ENTRY_OFF + 0xC))  # call callee
    blob[0xC] = 0xC3  # ret
    off = _CALLEE_OFF - _ENTRY_OFF
    blob[off : off + 3] = b"\x48\x8d\x05"
    blob[off + 3 : off + 7] = struct.pack("<i", callee_disp)  # lea rax,[rip+callee_disp]
    blob[off + 7] = 0xC3  # ret
    return bytes(blob)


def _segment(
    name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int,
    maxprot: int, initprot: int, sects: bytes = b"",
) -> bytes:
    nsects = 1 if sects else 0
    body = struct.pack("<II", 0x19, 72 + len(sects)) + name.encode().ljust(16, b"\x00")
    body += struct.pack("<QQQQ", vmaddr, vmsize, fileoff, filesize)
    body += struct.pack("<iiII", maxprot, initprot, nsects, 0)
    return body + sects


def _section(sectname: str, segname: str, addr: int, size: int, off: int, flags: int) -> bytes:
    body = sectname.encode().ljust(16, b"\x00") + segname.encode().ljust(16, b"\x00")
    body += struct.pack("<QQ", addr, size)
    body += struct.pack("<IIIIIIII", off, 0, 0, 0, flags, 0, 0, 0)
    return body


def _write_macho(path: Path) -> None:
    code = _text_code()
    text_sect = _section(
        "__text", "__TEXT", _TEXT_BASE + _ENTRY_OFF, len(code), _ENTRY_OFF, 0x80000400
    )
    data_sect = _section("__data", "__DATA", _TEXT_BASE + 0x1000, 0x20, 0x1000, 0)
    cmds = _segment("__PAGEZERO", 0, _TEXT_BASE, 0, 0, 0, 0)
    cmds += _segment("__TEXT", _TEXT_BASE, 0x1000, 0, 0x1000, 5, 5, text_sect)
    cmds += _segment("__DATA", _TEXT_BASE + 0x1000, 0x1000, 0x1000, 0x1000, 7, 3, data_sect)
    cmds += struct.pack("<IIQQ", 0x80000028, 24, _ENTRY_OFF, 0)  # LC_MAIN
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIII", 0x01000007, 3, 2, 4, len(cmds))
    header += struct.pack("<II", 0, 0)
    image = bytearray((header + cmds).ljust(0x1000, b"\x00"))
    image[_ENTRY_OFF : _ENTRY_OFF + len(code)] = code
    image += b"\x00" * 0x1000  # __DATA page
    image[_DATA_OFF : _DATA_OFF + 16] = b"macho-dataxref\x00\x00"
    path.write_bytes(bytes(image))


def _coord(value: object) -> tuple[Any, ...]:
    assert isinstance(value, dict), value
    assert set(value) == _COORD_KEYS, value
    return (value["module"], value["rva"], value["va"], value["architecture"])


def _coord_at(items: list[Any], object_field: str, va: int) -> tuple[Any, ...] | None:
    for item in items:
        if isinstance(item, dict):
            obj = item.get(object_field)
            if isinstance(obj, dict) and obj.get("va") == va:
                return _coord(obj)
    return None


@pytest.mark.integration
def test_m11_r2_and_ghidra_agree_on_macho_data_xrefs(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — Mach-O data-xref Gate not run (skip != pass)")
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")

    binary = tmp_path / "dataxref.macho"
    _write_macho(binary)
    entry_va = _TEXT_BASE + _ENTRY_OFF
    callee_va = _TEXT_BASE + _CALLEE_OFF
    data_va = _TEXT_BASE + _DATA_OFF

    service = AnalysisService(Settings.load())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session["target"] == "macho", session
    assert session["architecture"] == _ARCH, session
    sid = str(session["id"])

    # Both engines recover the two functions; the lea sites coincide with their
    # entries, so the data-ref sites below are exactly these two addresses.
    r2_funcs = service.r2_functions(sid, timeout=60.0)
    assert r2_funcs.ok and r2_funcs.data is not None, r2_funcs.error
    gh_funcs = service.ghidra_functions(sid, limit=64, timeout=300.0)
    assert gh_funcs.ok and gh_funcs.data is not None, gh_funcs.error
    r2_fn_items = r2_funcs.data.get("items", [])
    gh_fn_items = gh_funcs.data.get("items", [])
    for va in (entry_va, callee_va):
        assert _coord_at(r2_fn_items, "address", va) is not None, r2_fn_items
        assert _coord_at(gh_fn_items, "entry_address", va) is not None, gh_fn_items

    expected_sites = {
        (binary.name, _ENTRY_OFF, entry_va, _ARCH),
        (binary.name, _CALLEE_OFF, callee_va, _ARCH),
    }
    data_coord = (binary.name, _DATA_OFF, data_va, _ARCH)

    # r2: axtj on the datum, data references only (never control flow).
    r2_xrefs = service.r2_xrefs_to(sid, data_va, timeout=60.0)
    assert r2_xrefs.ok and r2_xrefs.data is not None, r2_xrefs.error
    r2_items = [
        i
        for i in r2_xrefs.data.get("items", [])
        if "CALL" not in str(i.get("type")) and "JUMP" not in str(i.get("type"))
    ]
    r2_sites = {_coord(i.get("from_address")) for i in r2_items}
    assert r2_sites == expected_sites, sorted(r2_sites)
    # axtj is queried *by* the datum, so the target is implicit; r2 confirms it
    # by resolving the operand to the __data datum rather than a bare address.
    assert all("__data" in str(i.get("refname")) for i in r2_items), r2_items

    # Ghidra: references to the datum, data kinds only.
    gh_xrefs = service.ghidra_xrefs(sid, hex(data_va), limit=64, timeout=300.0)
    assert gh_xrefs.ok and gh_xrefs.data is not None, gh_xrefs.error
    gh_items = [i for i in gh_xrefs.data.get("items", []) if str(i.get("type")) in _DATA_KINDS]
    gh_sites = {_coord(i.get("from_address")) for i in gh_items}
    assert gh_sites == expected_sites, sorted(gh_sites)
    assert {_coord(i.get("to_address")) for i in gh_items} == {data_coord}, gh_items

    # The two engines converge to the byte on both the readers and the datum.
    assert r2_sites == gh_sites
