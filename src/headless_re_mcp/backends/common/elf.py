"""Pure-stdlib structural reader for an ELF binary (Linux executable / .so).

Native code is a first-class reverse-engineering target -- an Android app's
``lib/**/*.so``, a Linux executable, an ELF malware sample -- yet the only way to
open one here was through r2 or Ghidra, external tools that are not always
installed. The ELF header, section table and dynamic array are exact,
well-documented structures, so summarize_elf reads them with the stdlib alone:
the bitness/endianness/type/machine/entry from the header, the section list
(names, types, flags, addresses, sizes) from the section table, and the shared
library dependencies (DT_NEEDED), the SONAME and the run-time search path from
the .dynamic section -- the offline ``readelf -h -S -d`` triage an analyst reads
first, plus whether the binary is stripped.

Both ELF classes (32- and 64-bit) and both byte orders are handled. The header
walk is exact; the section and dynamic tables are followed defensively -- an
offset or count that leaves the file contributes a warning, not an exception --
and every name, list and the section page are bounded.
"""

from __future__ import annotations

import struct
from typing import Any

JsonObject = dict[str, Any]

_ELF_MAGIC = b"\x7fELF"
_MAX_NAME = 256
_MAX_SECTIONS = 4096
_MAX_NEEDED = 1024
_MAX_DYN_ENTRIES = 65536
_MAX_WARNINGS = 32

_OSABI = {
    0: "System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "Linux",
    6: "Solaris",
    9: "FreeBSD",
    12: "OpenBSD",
    64: "ARM EABI",
    97: "ARM",
}

_ETYPE = {
    0: "none",
    1: "relocatable",
    2: "executable",
    3: "shared object",
    4: "core dump",
}

_MACHINE = {
    0: "none",
    2: "SPARC",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SuperH",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

_SH_TYPE = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
}

# Dynamic-section tags this reader acts on.
_DT_NULL = 0
_DT_NEEDED = 1
_DT_SONAME = 14
_DT_RPATH = 15
_DT_RUNPATH = 29


class ElfParseError(ValueError):
    """Bytes that are not an ELF binary.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name. Raised only for the
    header; a bad section or dynamic entry is a warning, not a failure.
    """


def _name_at(table: bytes, offset: int) -> str:
    """A NUL-terminated name at ``offset`` in a string table, bounded and safe."""
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    raw = table[offset : end if end != -1 else len(table)]
    return raw.decode("utf-8", errors="replace")[:_MAX_NAME]


def _section_flags(flags: int) -> str:
    letters = ((0x2, "A"), (0x4, "X"), (0x1, "W"), (0x10, "M"), (0x20, "S"), (0x200, "T"))
    return "".join(letter for bit, letter in letters if flags & bit)


def summarize_elf(data: bytes) -> JsonObject:
    """Structural summary of an ELF binary: header, sections and dependencies.

    Raises ElfParseError when the bytes are not an ELF (bad magic, unknown class
    or byte order, or a header that does not fit). The header fields are read
    exactly; the section table is walked with each entry bounds-checked, and the
    shared-library dependencies come from the .dynamic section resolved through
    .dynstr -- a corrupt offset yields a warning and is skipped, never an
    exception.
    """
    if len(data) < 20 or data[:4] != _ELF_MAGIC:
        raise ElfParseError("not an ELF file: missing the 0x7f 'ELF' magic")

    ei_class = data[4]
    ei_data = data[5]
    ei_osabi = data[7]
    if ei_class == 1:
        bits = 32
    elif ei_class == 2:
        bits = 64
    else:
        raise ElfParseError(f"unknown ELF class {ei_class}")
    if ei_data == 1:
        endian, endian_name = "<", "little"
    elif ei_data == 2:
        endian, endian_name = ">", "big"
    else:
        raise ElfParseError(f"unknown ELF data encoding {ei_data}")

    if bits == 64:
        hdr_fmt = endian + "HHIQQQIHHHHHH"
        hdr_size = 64
        sh_fmt = endian + "IIQQQQIIQQ"
        sh_size = 64
    else:
        hdr_fmt = endian + "HHIIIIIHHHHHH"
        hdr_size = 52
        sh_fmt = endian + "IIIIIIIIII"
        sh_size = 40
    if len(data) < hdr_size:
        raise ElfParseError("truncated ELF header")

    (
        e_type,
        e_machine,
        _e_version,
        e_entry,
        _e_phoff,
        e_shoff,
        e_flags,
        _e_ehsize,
        _e_phentsize,
        e_phnum,
        _e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from(hdr_fmt, data, 16)

    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    # The section-name string table, needed to name every other section.
    shstrtab = b""
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        base = e_shoff + e_shstrndx * sh_size
        if base + sh_size <= len(data):
            entry = struct.unpack_from(sh_fmt, data, base)
            off, size = entry[4], entry[5]
            if off + size <= len(data):
                shstrtab = data[off : off + size]
        else:
            warn("section-name string table header is past end of file")
    elif e_shoff and e_shnum:
        warn("section-name string table index is out of range")

    has_sections = bool(e_shoff and e_shnum)
    sections: list[JsonObject] = []
    dynamic_off = 0
    dynamic_size = 0
    dynstr = b""
    has_symtab = False
    if has_sections:
        if e_shnum > _MAX_SECTIONS:
            warn(f"section count {e_shnum} exceeds cap; listing truncated")
        for index in range(min(e_shnum, _MAX_SECTIONS)):
            base = e_shoff + index * sh_size
            if base + sh_size > len(data):
                warn(f"section header {index} is past end of file")
                break
            entry = struct.unpack_from(sh_fmt, data, base)
            name = _name_at(shstrtab, entry[0])
            sh_type, sh_flags, sh_addr, sh_offset, sh_size_val = (
                entry[1],
                entry[2],
                entry[3],
                entry[4],
                entry[5],
            )
            sections.append(
                {
                    "name": name,
                    "type": _SH_TYPE.get(sh_type, f"0x{sh_type:x}"),
                    "type_raw": sh_type,
                    "flags": _section_flags(sh_flags),
                    "addr": f"0x{sh_addr:x}",
                    "offset": sh_offset,
                    "size": sh_size_val,
                }
            )
            if name == ".dynstr" and sh_offset + sh_size_val <= len(data):
                dynstr = data[sh_offset : sh_offset + sh_size_val]
            if name == ".dynamic":
                dynamic_off, dynamic_size = sh_offset, sh_size_val
            if sh_type == 2 or name == ".symtab":
                has_symtab = True

    needed: list[str] = []
    soname: str | None = None
    runpath: str | None = None
    rpath: str | None = None
    if dynamic_off:
        dyn_fmt = endian + ("qQ" if bits == 64 else "iI")
        dyn_entry = 16 if bits == 64 else 8
        available = dynamic_size // dyn_entry if dynamic_size else _MAX_DYN_ENTRIES
        for index in range(min(available, _MAX_DYN_ENTRIES)):
            eoff = dynamic_off + index * dyn_entry
            if eoff + dyn_entry > len(data):
                warn("dynamic section extends past end of file")
                break
            tag, value = struct.unpack_from(dyn_fmt, data, eoff)
            if tag == _DT_NULL:
                break
            if tag == _DT_NEEDED:
                if len(needed) < _MAX_NEEDED:
                    needed.append(_name_at(dynstr, value))
            elif tag == _DT_SONAME:
                soname = _name_at(dynstr, value)
            elif tag == _DT_RUNPATH:
                runpath = _name_at(dynstr, value)
            elif tag == _DT_RPATH:
                rpath = _name_at(dynstr, value)

    return {
        "class": f"ELF{bits}",
        "bitness": bits,
        "endianness": endian_name,
        "os_abi": _OSABI.get(ei_osabi, f"0x{ei_osabi:x}"),
        "type": _ETYPE.get(e_type, f"0x{e_type:x}"),
        "type_raw": e_type,
        "machine": _MACHINE.get(e_machine, f"0x{e_machine:x}"),
        "machine_raw": e_machine,
        "entry": f"0x{e_entry:x}",
        "flags": f"0x{e_flags:x}",
        "section_count": e_shnum,
        "program_header_count": e_phnum,
        "has_sections": has_sections,
        "sections": sections,
        "sections_listed": len(sections),
        "needed": needed,
        "soname": soname,
        "runpath": runpath,
        "rpath": rpath,
        "stripped": not has_symtab,
        "warnings": warnings,
    }
