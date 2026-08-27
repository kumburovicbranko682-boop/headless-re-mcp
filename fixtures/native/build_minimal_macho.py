"""Generate ``minimal.macho``: a tiny but real 64-bit Mach-O executable.

The native reverse-engineering line is proven end to end on ELF against real
system binaries (``/bin/ls``, ``libc.so.6``), but the Mach-O half had only
synthetic unit coverage of the stdlib fact reader -- no gate ever opened a
Mach-O through a real tool, because a Linux CI runner has no macOS binary to
point at. This hand-writes the smallest Mach-O that radare2 parses as a real
image: a ``__PAGEZERO`` and a ``__TEXT`` segment (with a ``__text`` code
section carrying a real function body and a ``__cstring`` section carrying a
marker string), an ``LC_MAIN`` entry point so analysis seeds a function, and an
``LC_UUID``. No macOS toolchain is required; the output is deterministic and
committed as ``minimal.macho`` next to this file.

Run ``python fixtures/native/build_minimal_macho.py`` to regenerate it.
"""

from __future__ import annotations

import struct
from pathlib import Path

# A recognizable literal the r2 gate asserts on, proving the string scan ran on
# our bytes and not on some incidental data.
MARKER = b"headless-macho-fixture\x00"
# push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret -- a real, analyzable body.
CODE = b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3"

_MH_MAGIC_64 = 0xFEEDFACF
_CPU_TYPE_X86_64 = 0x01000007
_CPU_SUBTYPE_X86_64_ALL = 0x00000003
_MH_EXECUTE = 2
_MH_NOUNDEFS = 0x1
_MH_DYLDLINK = 0x4
_MH_PIE = 0x00200000
_LC_SEGMENT_64 = 0x19
_LC_UUID = 0x1B
_LC_MAIN = 0x80000028
_S_CSTRING_LITERALS = 0x00000002
_S_ATTR_PURE_INSTRUCTIONS_SOME = 0x80000400
_VM_BASE = 0x100000000


def _seg64(
    name: str,
    vmaddr: int,
    vmsize: int,
    fileoff: int,
    filesize: int,
    maxprot: int,
    initprot: int,
    nsects: int,
    flags: int,
) -> bytes:
    return (
        struct.pack("<II", _LC_SEGMENT_64, 72 + 80 * nsects)
        + name.encode().ljust(16, b"\x00")
        + struct.pack("<QQQQ", vmaddr, vmsize, fileoff, filesize)
        + struct.pack("<iiII", maxprot, initprot, nsects, flags)
    )


def _sect64(sect: str, seg: str, addr: int, size: int, offset: int, flags: int) -> bytes:
    return (
        sect.encode().ljust(16, b"\x00")
        + seg.encode().ljust(16, b"\x00")
        + struct.pack("<QQII", addr, size, offset, 0)
        + struct.pack("<IIIII", 0, 0, flags, 0, 0)
        + struct.pack("<I", 0)
    )


def build() -> bytes:
    seg_pagezero = 72
    seg_text = 72 + 80 * 2  # two sections: __text and __cstring
    lc_main = 24
    lc_uuid = 24
    sizeofcmds = seg_pagezero + seg_text + lc_main + lc_uuid
    ncmds = 4
    code_off = 32 + sizeofcmds
    cstr_off = code_off + len(CODE)
    total = cstr_off + len(MARKER)

    header = struct.pack(
        "<IiiIIII",
        _MH_MAGIC_64,
        _CPU_TYPE_X86_64,
        _CPU_SUBTYPE_X86_64_ALL,
        _MH_EXECUTE,
        ncmds,
        sizeofcmds,
        _MH_NOUNDEFS | _MH_DYLDLINK | _MH_PIE,
    ) + struct.pack("<I", 0)
    pagezero = _seg64("__PAGEZERO", 0, _VM_BASE, 0, 0, 0, 0, 0, 0)
    text_sect = _sect64(
        "__text", "__TEXT", _VM_BASE + code_off, len(CODE), code_off, _S_ATTR_PURE_INSTRUCTIONS_SOME
    )
    cstr_sect = _sect64(
        "__cstring", "__TEXT", _VM_BASE + cstr_off, len(MARKER), cstr_off, _S_CSTRING_LITERALS
    )
    text = _seg64("__TEXT", _VM_BASE, 0x1000, 0, total, 5, 5, 2, 0) + text_sect + cstr_sect
    main = struct.pack("<IIQQ", _LC_MAIN, 24, code_off, 0)  # entryoff, stacksize
    uuid = struct.pack("<II", _LC_UUID, 24) + bytes(range(16))
    blob = header + pagezero + text + main + uuid + CODE + MARKER
    assert len(blob) == total, (len(blob), total)
    return blob


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "minimal.macho"
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
