"""M11 Ghidra decompile gate: real pseudo-C recovered from a Mach-O.

The other Ghidra decompile gates feed the DecompInterface an ELF, an ARM ELF, or
a mingw PE; none feed it a Mach-O, so nothing carried the macOS/iOS container up
through the decompiler. This closes that gap for a thin x86_64 image (base
0x100000000) and a thin arm64 image (base 0x140000000): a two-function __text
(an ``LC_MAIN`` entry that calls a callee 0x10 later, both return) is imported by
Ghidra's Mach-O loader, and this gate asserts the decompiler

* renders the entry as a named ``entry`` function whose body calls the callee
  (so the intra-__text call survived loader + analyzer + decompiler),
* attaches the shared ``entry_address`` coordinate object to the decompile
  payload -- the Mach-O-mode enrichment the r2<->Ghidra coords gate pins at the
  function level, here at the decompile level, and
* is address-scoped: decompiling the callee yields a different function that
  does not mention the entry, and an unmapped address yields an empty
  decompilation rather than an error.

No toolchain emits Mach-O on Linux, so the fixture is hand-built and its bodies
are minimal; the ELF and PE decompile gates already pin rich control flow where
a compiler exists. This gate's point is that the *Mach-O container* reaches the
decompiler at all. skip != pass when Ghidra is missing.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraClient

_ANALYZE_TIMEOUT_S = 300.0
_ENTRY_OFF = 0x400
_CALLEE_OFF = 0x410
_X64 = (0x01000007, 3, "x64", 0x100000000, b"\xe8\x0b\x00\x00\x00\xc3")  # call rel32 ; ret
_ARM64 = (0x0100000C, 0, "arm64", 0x140000000, b"\x04\x00\x00\x94\xc0\x03\x5f\xd6")  # bl ; ret


def _segment(
    name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int,
    maxprot: int, initprot: int, sects: bytes = b"",
) -> bytes:
    nsects = 1 if sects else 0
    body = struct.pack("<II", 0x19, 72 + len(sects)) + name.encode().ljust(16, b"\x00")
    body += struct.pack("<QQQQ", vmaddr, vmsize, fileoff, filesize)
    body += struct.pack("<iiII", maxprot, initprot, nsects, 0)
    return body + sects


def _write_macho(
    path: Path, *, cputype: int, cpusubtype: int, text_base: int, entry: bytes
) -> None:
    # entry at _ENTRY_OFF calls the callee at _CALLEE_OFF; the callee is a ret.
    code = bytearray(_CALLEE_OFF - _ENTRY_OFF + 4)
    code[0 : len(entry)] = entry
    ret = b"\xc3" if cputype == 0x01000007 else b"\xc0\x03\x5f\xd6"
    code[_CALLEE_OFF - _ENTRY_OFF : _CALLEE_OFF - _ENTRY_OFF + len(ret)] = ret

    section = b"__text".ljust(16, b"\x00") + b"__TEXT".ljust(16, b"\x00")
    section += struct.pack("<QQ", text_base + _ENTRY_OFF, len(code))
    section += struct.pack("<IIIIIIII", _ENTRY_OFF, 0, 0, 0, 0x80000400, 0, 0, 0)

    cmds = _segment("__PAGEZERO", 0, text_base, 0, 0, 0, 0)
    cmds += _segment("__TEXT", text_base, 0x1000, 0, 0x1000, 5, 5, section)
    cmds += struct.pack("<IIQQ", 0x80000028, 24, _ENTRY_OFF, 0)  # LC_MAIN
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIII", cputype, cpusubtype, 2, 3, len(cmds))
    header += struct.pack("<II", 0, 0)
    image = bytearray((header + cmds).ljust(0x1000, b"\x00"))
    image[_ENTRY_OFF : _ENTRY_OFF + len(code)] = code
    path.write_bytes(bytes(image))


def _ghidra() -> GhidraClient | None:
    home = os.environ.get("HEADLESS_RE_GHIDRA_HOME")
    if not home:
        return None
    client = GhidraClient(home=Path(home))
    return client if client.available else None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("cputype", "cpusubtype", "arch", "text_base", "entry_code"),
    [_X64, _ARM64],
    ids=["x86_64", "arm64"],
)
def test_m11_ghidra_decompiles_a_macho_function(
    tmp_path: Path, cputype: int, cpusubtype: int, arch: str, text_base: int, entry_code: bytes
) -> None:
    client = _ghidra()
    if client is None:
        pytest.skip(
            "Ghidra not configured (HEADLESS_RE_GHIDRA_HOME) or java missing — skip != pass"
        )
    binary = tmp_path / f"{arch}.macho"
    _write_macho(
        binary, cputype=cputype, cpusubtype=cpusubtype, text_base=text_base, entry=entry_code
    )
    entry_va = text_base + _ENTRY_OFF
    callee_va = text_base + _CALLEE_OFF
    callee_hex = f"{callee_va:x}"
    project = tmp_path / "ghidra_project"

    funcs = client.functions(binary, project, limit=64, timeout=_ANALYZE_TIMEOUT_S)
    names = {str(i.get("name")): str(i.get("entry")) for i in funcs["items"]}
    # LC_MAIN gives the entry function; following its call gives the callee.
    assert "entry" in names, names
    assert any(callee_hex in n or callee_hex == e for n, e in names.items()), names

    # The entry, decompiled through the Mach-O loader: named, complete, and its
    # body calls the callee (the intra-__text call survived the whole pipeline).
    outer = client.decompile(binary, project, hex(entry_va), timeout=_ANALYZE_TIMEOUT_S)
    assert outer.get("mode") == "decompile"
    assert outer.get("function") == "entry", outer
    assert str(outer.get("entry")).lstrip("0") == f"{entry_va:x}".lstrip("0"), outer
    assert outer.get("truncated") is False
    # The decompile payload carries the same Mach-O coordinate object the
    # functions export attaches, here on the top-level entry.
    assert outer.get("entry_address") == {
        "module": binary.name,
        "rva": _ENTRY_OFF,
        "va": entry_va,
        "architecture": arch,
    }, outer
    c = str(outer.get("decompiled"))
    assert c.strip(), "empty decompilation"
    assert "entry" in c, c
    assert callee_hex in c, c  # the callee call, e.g. FUN_100000410()

    # Address scoping: the callee decompiles to a different function that does
    # not mention the entry address.
    inner = client.decompile(binary, project, hex(callee_va), timeout=_ANALYZE_TIMEOUT_S)
    assert inner.get("function") != "entry", inner
    assert f"{entry_va:x}" not in str(inner.get("decompiled")), inner

    # Contract: an address outside the mapped image yields an empty
    # decompilation (no function/entry), not an error.
    empty = client.decompile(binary, project, "0x0", timeout=_ANALYZE_TIMEOUT_S)
    assert empty.get("mode") == "decompile"
    assert empty.get("function") is None, empty
    assert str(empty.get("decompiled")) == "", empty
