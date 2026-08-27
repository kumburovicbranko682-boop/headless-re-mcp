"""M11 cross-engine gate: r2 and Ghidra agree per fat Mach-O slice.

The thin Mach-O agreement gate pins both engines to one coordinate frame for a
single-arch image. A universal binary adds the selection problem, and each
engine solves it differently: r2 takes ``-a``/``-b`` and reads the fat in
place, while Ghidra's headless importer offers no load spec for the fat at all
(and ``-processor`` merely forces a language onto every slice, verified wrong),
so the client carves the requested slice and imports the carve. This gate
proves the two mechanisms land on the *same* coordinates: one session on a
real x86_64+arm64 universal binary, driven through the AnalysisService with
``slice_arch``, must for each slice have both engines

* report the identical top-level frame -- the fat's module name with the
  *selected slice's own* base and architecture,
* recover the slice's entry and callee functions and attach identical
  coordinate objects at each, and
* resolve the entry -> callee call site to the identical ``from_address``.

And because an unselected fat cannot mean anything in Ghidra, the service must
reject slice-less and absent-slice ghidra calls as invalid_params -- naming
the slices that would work -- before any headless run is spawned. The slices
are the same hand-built two-function LC_MAIN images the thin gate uses.
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
_ENTRY_OFF = 0x400
_CALLEE_OFF = 0x410
# (cputype, cpusubtype, arch label, __TEXT base) per slice.
_X64 = (0x01000007, 3, "x64", 0x100000000)
_ARM64 = (0x0100000C, 0, "arm64", 0x140000000)


def _entry_code(arch: str) -> bytes:
    """Entry at +0x0 calls the callee at +0x10; both return."""
    blob = bytearray(_CALLEE_OFF - _ENTRY_OFF + 4)
    if arch == "x64":
        blob[0:6] = b"\xe8\x0b\x00\x00\x00\xc3"
        blob[0x10] = 0xC3
    else:
        blob[0:8] = b"\x04\x00\x00\x94\xc0\x03\x5f\xd6"
        blob[0x10:0x14] = b"\xc0\x03\x5f\xd6"
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


def _thin_macho(cputype: int, cpusubtype: int, text_base: int, code: bytes) -> bytes:
    """The thin gate's fixture as bytes: __PAGEZERO, __TEXT+__text, LC_MAIN."""
    sect = b"__text".ljust(16, b"\x00") + b"__TEXT".ljust(16, b"\x00")
    sect += struct.pack("<QQ", text_base + _ENTRY_OFF, len(code))
    sect += struct.pack("<IIIIIIII", _ENTRY_OFF, 0, 0, 0, 0x80000400, 0, 0, 0)
    cmds = _segment("__PAGEZERO", 0, text_base, 0, 0, 0, 0)
    cmds += _segment("__TEXT", text_base, 0x1000, 0, 0x1000, 5, 5, sect)
    cmds += struct.pack("<IIQQ", 0x80000028, 24, _ENTRY_OFF, 0)  # LC_MAIN
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIII", cputype, cpusubtype, 2, 3, len(cmds))
    header += struct.pack("<II", 0, 0)
    image = bytearray((header + cmds).ljust(0x1000, b"\x00"))
    image[_ENTRY_OFF : _ENTRY_OFF + len(code)] = code
    return bytes(image)


def _write_fat(path: Path) -> None:
    """A real x86_64+arm64 universal binary, page-aligned like lipo emits."""
    slices = [
        (cputype, cpusubtype, _thin_macho(cputype, cpusubtype, base, _entry_code(arch)))
        for cputype, cpusubtype, arch, base in (_X64, _ARM64)
    ]
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(slices))
    cursor = 0x4000
    for cputype, cpusubtype, blob in slices:
        header += struct.pack(">IIIII", cputype, cpusubtype, cursor, len(blob), 14)
        cursor += (len(blob) + 0x3FFF) & ~0x3FFF
    image = bytearray(header)
    cursor = 0x4000
    for _cputype, _cpusubtype, blob in slices:
        image = image.ljust(cursor, b"\x00") + blob
        cursor += (len(blob) + 0x3FFF) & ~0x3FFF
    path.write_bytes(bytes(image))


def _coord(value: object) -> dict[str, Any]:
    assert isinstance(value, dict), value
    assert set(value) == _COORD_KEYS, value
    return value


def _frame(payload: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (payload.get("module"), payload.get("image_base"), payload.get("architecture"))


def _coord_at(items: list[Any], object_field: str, va: int) -> dict[str, Any] | None:
    for item in items:
        if isinstance(item, dict):
            obj = item.get(object_field)
            if isinstance(obj, dict) and obj.get("va") == va:
                return _coord(obj)
    return None


def _skip_unless_both_engines() -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — fat Mach-O Gate not run (skip != pass)")
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")


def _fat_session(service: AnalysisService, binary: Path) -> str:
    _write_fat(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert session["target"] == "macho", session
    macho = session.get("metadata", {}).get("macho", {})
    assert macho.get("fat") is True, session
    found = sorted(str(s.get("architecture")) for s in macho.get("slices", []))
    assert found == ["arm64", "x64"], session
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.parametrize(("slice_spec",), [(_X64,), (_ARM64,)], ids=["x86_64", "arm64"])
def test_m11_r2_and_ghidra_agree_on_a_fat_slice(
    tmp_path: Path, slice_spec: tuple[int, int, str, int]
) -> None:
    _skip_unless_both_engines()
    _cputype, _cpusubtype, arch, text_base = slice_spec
    binary = tmp_path / "universal.macho"
    service = AnalysisService(Settings.load())
    sid = _fat_session(service, binary)
    entry_va = text_base + _ENTRY_OFF
    callee_va = text_base + _CALLEE_OFF

    r2_funcs = service.r2_functions(sid, timeout=60.0, slice_arch=arch)
    assert r2_funcs.ok and r2_funcs.data is not None, r2_funcs.error
    assert r2_funcs.data.get("parsed") is True, r2_funcs.data

    gh_funcs = service.ghidra_functions(sid, limit=64, timeout=300.0, slice_arch=arch)
    assert gh_funcs.ok and gh_funcs.data is not None, gh_funcs.error
    assert gh_funcs.data.get("mode") == "functions", gh_funcs.data

    # Agreement 1: the frame is the fat's module with the selected slice's own
    # base and architecture -- from r2's -a/-b read of the fat in place, and
    # from Ghidra's import of the carved slice.
    expected_frame = (binary.name, text_base, arch)
    assert _frame(r2_funcs.data) == expected_frame, r2_funcs.data
    assert _frame(gh_funcs.data) == expected_frame, gh_funcs.data

    # Agreement 2: entry and callee, identical coordinate objects.
    r2_items = r2_funcs.data.get("items", [])
    gh_items = gh_funcs.data.get("items", [])
    for va, off in ((entry_va, _ENTRY_OFF), (callee_va, _CALLEE_OFF)):
        expected = {"module": binary.name, "rva": off, "va": va, "architecture": arch}
        assert _coord_at(r2_items, "address", va) == expected, (va, r2_items)
        assert _coord_at(gh_items, "entry_address", va) == expected, (va, gh_items)

    # Agreement 3: the entry -> callee call site, identical from_address.
    expected_site = {"module": binary.name, "rva": _ENTRY_OFF, "va": entry_va, "architecture": arch}
    r2_xrefs = service.r2_xrefs_to(sid, callee_va, timeout=60.0, slice_arch=arch)
    assert r2_xrefs.ok and r2_xrefs.data is not None, r2_xrefs.error
    r2_calls = [
        _coord(i.get("from_address"))
        for i in r2_xrefs.data.get("items", [])
        if "CALL" in str(i.get("type"))
    ]
    assert expected_site in r2_calls, r2_xrefs.data.get("items")

    gh_xrefs = service.ghidra_xrefs(sid, hex(callee_va), limit=64, timeout=300.0, slice_arch=arch)
    assert gh_xrefs.ok and gh_xrefs.data is not None, gh_xrefs.error
    gh_calls = [
        _coord(i.get("from_address"))
        for i in gh_xrefs.data.get("items", [])
        if "CALL" in str(i.get("type"))
    ]
    assert expected_site in gh_calls, gh_xrefs.data.get("items")


@pytest.mark.integration
def test_m11_ghidra_on_a_fat_demands_a_slice_before_any_headless_run(tmp_path: Path) -> None:
    """The contract half of the gate: no slice, no JVM.

    Only Ghidra availability gates this test -- the rejection happens in the
    service before any engine is reached, and takes milliseconds, not a
    headless import.
    """
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home or not GhidraClient(home=Path(home)).available:
        pytest.skip("Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) — skip != pass")
    binary = tmp_path / "universal.macho"
    service = AnalysisService(Settings.load())
    sid = _fat_session(service, binary)

    unselected = service.ghidra_functions(sid, limit=64, timeout=300.0)
    assert unselected.ok is False
    assert unselected.error is not None
    assert unselected.error.code == "invalid_params", unselected.error
    assert "slice_arch" in unselected.error.message
    assert unselected.error.details.get("available_slices") == ["arm64", "x64"]

    absent = service.ghidra_functions(sid, limit=64, timeout=300.0, slice_arch="arm")
    assert absent.ok is False
    assert absent.error is not None
    assert absent.error.code == "invalid_params", absent.error
    assert absent.error.details.get("available_slices") == ["arm64", "x64"]
