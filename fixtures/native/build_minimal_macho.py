"""Generate ``minimal.macho``: a tiny but real 64-bit Mach-O executable.

The native reverse-engineering line is proven end to end on ELF against real
system binaries (``/bin/ls``, ``libc.so.6``), but the Mach-O half had only
synthetic unit coverage of the stdlib fact reader -- no gate ever opened a
Mach-O through a real tool, because a Linux CI runner has no macOS binary to
point at. This hand-writes the smallest Mach-O that radare2 parses as a real
image: a ``__PAGEZERO`` and a ``__TEXT`` segment (with a ``__text`` code
section carrying a real function body and a ``__cstring`` section carrying a
marker string), an ``LC_LOAD_DYLINKER``/``LC_LOAD_DYLIB`` pair so the dynamic
identity facts (interpreter, dylibs) are populated the way every real
executable populates them, an ``LC_MAIN`` entry point so analysis seeds a
function, an ``LC_UUID``, and an ``LC_SYMTAB``/``LC_DYSYMTAB`` pair whose
undefined imports include the ``___stack_chk_guard``/``___stack_chk_fail``
pair a clang ``-fstack-protector`` build pulls from libSystem -- so the
canary posture fact has a positive case radare2 independently confirms (r2
keys its own canary line on that import, reached through the dysymtab's
indirect-symbol table) -- an ``LC_RPATH`` so the @rpath search-path fact
(the ELF rpath/runpath analogue) has a positive case llvm-objdump confirms,
and an ``LC_BUILD_VERSION`` naming the target platform and minimum OS / SDK
versions the way every modern linker does, so the platform facts have a
positive case both llvm-objdump and radare2 (its ``os`` line) confirm.
Variable-length load commands are 8-byte aligned: the 64-bit Mach-O spec
requires it and llvm-objdump rejects the image otherwise (radare2 merely
tolerates 4-byte alignment, which is how the earlier misalignment went
unnoticed). No macOS toolchain is required; the output is deterministic and
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
# The dynamic-linkage identity of every real macOS executable: dyld as the
# interpreter and libSystem as the (at minimum) linked dylib.
DYLINKER = "/usr/lib/dyld"
DYLIB = "/usr/lib/libSystem.B.dylib"
# The @rpath search path an app-bundle binary typically bakes in; kept verbatim
# (unexpanded) by every reader, so it round-trips exactly.
RPATH = "@loader_path/../Frameworks"

# The stack-protector imports every hardened clang build carries; both the
# stdlib reader (string-table scan) and radare2 (undefined-import walk) derive
# their canary fact from these names.
SYMBOLS = ["_main", "___stack_chk_guard", "___stack_chk_fail"]

_MH_MAGIC_64 = 0xFEEDFACF
_CPU_TYPE_X86_64 = 0x01000007
_CPU_SUBTYPE_X86_64_ALL = 0x00000003
_MH_EXECUTE = 2
_MH_DYLDLINK = 0x4
_MH_PIE = 0x00200000
_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x02
_LC_DYSYMTAB = 0x0B
_LC_LOAD_DYLIB = 0x0C
_LC_LOAD_DYLINKER = 0x0E
_LC_UUID = 0x1B
_LC_MAIN = 0x80000028
_LC_RPATH = 0x8000001C
_LC_BUILD_VERSION = 0x32
_S_CSTRING_LITERALS = 0x00000002
_S_ATTR_PURE_INSTRUCTIONS_SOME = 0x80000400
_VM_BASE = 0x100000000


def _align8(value: int) -> int:
    # 64-bit load commands must be 8-byte aligned; llvm-objdump enforces this.
    return (value + 7) & ~7


def _lc_load_dylinker(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    total = _align8(12 + len(raw))  # cmd, cmdsize, name offset -- then the path
    return struct.pack("<III", _LC_LOAD_DYLINKER, total, 12) + raw.ljust(total - 12, b"\x00")


def _lc_load_dylib(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    total = _align8(24 + len(raw))  # dylib_command header is 24 bytes, then the name
    header = struct.pack(
        "<IIIIII", _LC_LOAD_DYLIB, total, 24, 0, 0x10000, 0x10000
    )  # name offset, timestamp, current/compat version
    return header + raw.ljust(total - 24, b"\x00")


def _lc_rpath(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    total = _align8(12 + len(raw))  # rpath_command is an lc_str like the dylinker's
    return struct.pack("<III", _LC_RPATH, total, 12) + raw.ljust(total - 12, b"\x00")


def _lc_build_version() -> bytes:
    # platform 1 (macOS), minos 13.0, sdk 14.2 -- versions in xxxx.yy.zz nibble
    # packing -- and no trailing build_tool_version entries (ntools 0).
    return struct.pack("<IIIIII", _LC_BUILD_VERSION, 24, 1, 0x000D0000, 0x000E0200, 0)


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


def _symtab_blob(code_addr: int) -> tuple[bytes, bytes]:
    """The nlist_64 rows plus string table for ``SYMBOLS``.

    ``_main`` is defined in section 1 at the entry point; the stack_chk pair
    are undefined externals (imports), exactly how a linker emits them.
    """
    strtab = b"\x00"
    nlists = b""
    for name in SYMBOLS:
        strx = len(strtab)
        strtab += name.encode() + b"\x00"
        if name == "_main":
            nlists += struct.pack("<IBBHQ", strx, 0x0F, 1, 0, code_addr)  # N_SECT | N_EXT
        else:
            nlists += struct.pack("<IBBHQ", strx, 0x01, 0, 0, 0)  # N_UNDF | N_EXT
    return nlists, strtab


def build() -> bytes:
    dylinker = _lc_load_dylinker(DYLINKER)
    dylib = _lc_load_dylib(DYLIB)
    rpath = _lc_rpath(RPATH)
    buildver = _lc_build_version()
    seg_pagezero = 72
    seg_text = 72 + 80 * 2  # two sections: __text and __cstring
    lc_main = 24
    lc_uuid = 24
    lc_symtab = 24
    lc_dysymtab = 80
    sizeofcmds = (
        seg_pagezero
        + seg_text
        + len(dylinker)
        + len(dylib)
        + len(rpath)
        + len(buildver)
        + lc_main
        + lc_uuid
        + lc_symtab
        + lc_dysymtab
    )
    ncmds = 10
    code_off = 32 + sizeofcmds
    cstr_off = code_off + len(CODE)
    total = cstr_off + len(MARKER)
    # radare2 reads dylib names with a fixed 256-byte buffer and rejects the
    # whole image if that read would run past EOF, so a file this small needs
    # tail padding to keep the name read in bounds.
    dylib_name_off = 32 + seg_pagezero + seg_text + len(dylinker) + 24
    padding = max(0, dylib_name_off + 256 - total)
    total += padding

    # The symbol machinery rides after the padding tail: nlist rows, the string
    # table, then the indirect-symbol table radare2 requires before it walks
    # the dysymtab's undefined range as imports.
    nlists, strtab = _symtab_blob(_VM_BASE + code_off)
    nundef = len(SYMBOLS) - 1
    symoff = total
    stroff = symoff + len(nlists)
    indirectoff = stroff + len(strtab)
    indirect = struct.pack(f"<{nundef}I", *range(1, 1 + nundef))
    total = indirectoff + len(indirect)
    symtab = struct.pack("<IIIIII", _LC_SYMTAB, 24, symoff, len(SYMBOLS), stroff, len(strtab))
    # dysymtab_command: one defined external (_main), then the undefined
    # imports, plus the indirect table; every other range is empty.
    dysymtab = struct.pack(
        "<20I", _LC_DYSYMTAB, 80, 0, 0, 0, 1, 1, nundef, *([0] * 6), indirectoff, nundef, 0, 0, 0, 0
    )

    header = struct.pack(
        "<IiiIIII",
        _MH_MAGIC_64,
        _CPU_TYPE_X86_64,
        _CPU_SUBTYPE_X86_64_ALL,
        _MH_EXECUTE,
        ncmds,
        sizeofcmds,
        _MH_DYLDLINK | _MH_PIE,  # undefined imports now exist, so no MH_NOUNDEFS
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
    blob = (
        header + pagezero + text + dylinker + dylib + rpath + buildver + main + uuid
    ) + symtab + dysymtab
    blob += CODE + MARKER
    blob += b"\x00" * padding
    blob += nlists + strtab + indirect
    assert len(blob) == total, (len(blob), total)
    return blob


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "minimal.macho"
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
