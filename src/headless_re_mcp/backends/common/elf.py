"""Pure-stdlib structural reader for an ELF binary (Linux executable / .so).

Native code is a first-class reverse-engineering target -- an Android app's
``lib/**/*.so``, a Linux executable, an ELF malware sample -- yet the only way to
open one here was through r2 or Ghidra, external tools that are not always
installed. The ELF header, section table, dynamic array and symbol tables are
exact, well-documented structures, so this module reads them with the stdlib
alone: summarize_elf gives the bitness/endianness/type/machine/entry from the
header, the section list (names, types, flags, addresses, sizes) from the
section table, and the shared library dependencies (DT_NEEDED), the SONAME and
the run-time search path from the .dynamic section -- the offline
``readelf -h -S -d`` triage an analyst reads first, plus whether the binary is
stripped. list_elf_symbols pages through .dynsym -- the import/export surface
that survives stripping -- naming each symbol with its binding, type and
whether it is imported (undefined) or exported (defined and visible).

Both ELF classes (32- and 64-bit) and both byte orders are handled. The header
walk is exact; the section, dynamic and symbol tables are followed defensively
-- an offset or count that leaves the file contributes a warning, not an
exception -- and every name, list and page is bounded.
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
_MAX_SYMBOL_PAGE = 1000

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

_SYM_BIND = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE"}
_SYM_TYPE = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "GNU_IFUNC",
}


class ElfParseError(ValueError):
    """Bytes that are not an ELF binary.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name. Raised only for the
    header; a bad section, dynamic or symbol entry is a warning, not a failure.
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


def _read_image(data: bytes) -> JsonObject:
    """Header fields plus the raw section table, shared by every elf.* reader.

    Raises ElfParseError when the bytes are not an ELF; returns a dict of the
    identification/header fields, the raw section records (integer fields as
    the file stores them, plus the resolved name) and the warnings gathered
    while walking the section table.
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
    if has_sections:
        if e_shnum > _MAX_SECTIONS:
            warn(f"section count {e_shnum} exceeds cap; listing truncated")
        for index in range(min(e_shnum, _MAX_SECTIONS)):
            base = e_shoff + index * sh_size
            if base + sh_size > len(data):
                warn(f"section header {index} is past end of file")
                break
            entry = struct.unpack_from(sh_fmt, data, base)
            sections.append(
                {
                    "name": _name_at(shstrtab, entry[0]),
                    "type": entry[1],
                    "flags": entry[2],
                    "addr": entry[3],
                    "offset": entry[4],
                    "size": entry[5],
                    "link": entry[6],
                    "entsize": entry[9],
                }
            )

    return {
        "bits": bits,
        "endian": endian,
        "endian_name": endian_name,
        "ei_osabi": ei_osabi,
        "e_type": e_type,
        "e_machine": e_machine,
        "e_entry": e_entry,
        "e_flags": e_flags,
        "e_phnum": e_phnum,
        "e_shnum": e_shnum,
        "has_sections": has_sections,
        "sections": sections,
        "warnings": warnings,
    }


def _section_named(image: JsonObject, name: str) -> JsonObject | None:
    sections: list[JsonObject] = image["sections"]
    for section in sections:
        if section["name"] == name:
            return section
    return None


def _table_bytes(data: bytes, section: JsonObject | None) -> bytes:
    """A section's raw contents, or b'' when it does not fit in the file."""
    if section is None:
        return b""
    off, size = section["offset"], section["size"]
    if off < 0 or size < 0 or off + size > len(data):
        return b""
    return data[off : off + size]


def summarize_elf(data: bytes) -> JsonObject:
    """Structural summary of an ELF binary: header, sections and dependencies.

    Raises ElfParseError when the bytes are not an ELF (bad magic, unknown class
    or byte order, or a header that does not fit). The header fields are read
    exactly; the section table is walked with each entry bounds-checked, and the
    shared-library dependencies come from the .dynamic section resolved through
    .dynstr -- a corrupt offset yields a warning and is skipped, never an
    exception.
    """
    image = _read_image(data)
    bits: int = image["bits"]
    endian: str = image["endian"]
    warnings: list[str] = image["warnings"]

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    sections: list[JsonObject] = []
    dynamic_off = 0
    dynamic_size = 0
    dynstr = b""
    has_symtab = False
    for raw in image["sections"]:
        sections.append(
            {
                "name": raw["name"],
                "type": _SH_TYPE.get(raw["type"], f"0x{raw['type']:x}"),
                "type_raw": raw["type"],
                "flags": _section_flags(raw["flags"]),
                "addr": f"0x{raw['addr']:x}",
                "offset": raw["offset"],
                "size": raw["size"],
            }
        )
        if raw["name"] == ".dynstr":
            dynstr = _table_bytes(data, raw) or dynstr
        if raw["name"] == ".dynamic":
            dynamic_off, dynamic_size = raw["offset"], raw["size"]
        if raw["type"] == 2 or raw["name"] == ".symtab":
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
        "endianness": image["endian_name"],
        "os_abi": _OSABI.get(image["ei_osabi"], f"0x{image['ei_osabi']:x}"),
        "type": _ETYPE.get(image["e_type"], f"0x{image['e_type']:x}"),
        "type_raw": image["e_type"],
        "machine": _MACHINE.get(image["e_machine"], f"0x{image['e_machine']:x}"),
        "machine_raw": image["e_machine"],
        "entry": f"0x{image['e_entry']:x}",
        "flags": f"0x{image['e_flags']:x}",
        "section_count": image["e_shnum"],
        "program_header_count": image["e_phnum"],
        "has_sections": image["has_sections"],
        "sections": sections,
        "sections_listed": len(sections),
        "needed": needed,
        "soname": soname,
        "runpath": runpath,
        "rpath": rpath,
        "stripped": not has_symtab,
        "warnings": warnings,
    }


def list_elf_symbols(data: bytes, *, offset: int = 0, limit: int = 200) -> JsonObject:
    """One page of the dynamic symbol table (.dynsym): imports and exports.

    The dynamic symbols are the binary's link surface -- the functions and
    objects it imports from shared libraries (undefined entries) and the ones
    it exports for others to call (defined GLOBAL/WEAK entries) -- and unlike
    .symtab they survive stripping. Each entry is named through the linked
    string table with its binding (GLOBAL/WEAK/LOCAL), type (FUNC/OBJECT/...),
    value, size and section index, plus imported/exported booleans so a caller
    can filter without re-deriving the ELF rules.

    Raises ElfParseError only when the bytes are not an ELF at all. A missing
    .dynsym (a statically linked or fully static binary) is an empty listing
    with a warning; a symbol record past end of file stops the page with a
    warning.
    """
    image = _read_image(data)
    bits: int = image["bits"]
    endian: str = image["endian"]
    warnings: list[str] = image["warnings"]

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    start = max(0, int(offset))
    window = max(1, min(int(limit), _MAX_SYMBOL_PAGE))

    dynsym = _section_named(image, ".dynsym")
    if dynsym is None:
        for raw in image["sections"]:
            if raw["type"] == 11:  # SHT_DYNSYM, in case the name was mangled
                dynsym = raw
                break

    total = 0
    symbols: list[JsonObject] = []
    if dynsym is None:
        warn("no .dynsym section: statically linked, or a relocatable object")
    else:
        # The string table for a symbol table is the section its sh_link names.
        raw_sections: list[JsonObject] = image["sections"]
        strtab = b""
        link = dynsym["link"]
        if 0 <= link < len(raw_sections):
            strtab = _table_bytes(data, raw_sections[link])
        if not strtab:
            strtab = _table_bytes(data, _section_named(image, ".dynstr"))
            if not strtab:
                warn("dynamic string table missing; symbol names unavailable")

        sym_size = 24 if bits == 64 else 16
        sym_fmt = endian + ("IBBHQQ" if bits == 64 else "IIIBBH")
        entsize = dynsym["entsize"] or sym_size
        if entsize < sym_size:
            warn(f"symbol entry size {entsize} too small; using {sym_size}")
            entsize = sym_size
        total = dynsym["size"] // entsize if entsize else 0

        for index in range(start, min(total, start + window)):
            eoff = dynsym["offset"] + index * entsize
            if eoff < 0 or eoff + sym_size > len(data):
                warn(f"symbol {index} is past end of file")
                break
            fields = struct.unpack_from(sym_fmt, data, eoff)
            if bits == 64:
                st_name, st_info, _st_other, st_shndx, st_value, st_size = fields
            else:
                st_name, st_value, st_size, st_info, _st_other, st_shndx = fields
            name = _name_at(strtab, st_name)
            bind = st_info >> 4
            sym_type = st_info & 0xF
            defined = st_shndx != 0
            symbols.append(
                {
                    "name": name,
                    "bind": _SYM_BIND.get(bind, f"0x{bind:x}"),
                    "type": _SYM_TYPE.get(sym_type, f"0x{sym_type:x}"),
                    "value": f"0x{st_value:x}",
                    "size": st_size,
                    "shndx": st_shndx,
                    "imported": bool(name) and not defined,
                    "exported": bool(name) and defined and bind in (1, 2, 10),
                }
            )

    return {
        "class": f"ELF{bits}",
        "symbols": symbols,
        "symbols_listed": len(symbols),
        "symbols_total": total,
        "imported_listed": sum(1 for s in symbols if s["imported"]),
        "exported_listed": sum(1 for s in symbols if s["exported"]),
        "offset": start,
        "limit": window,
        "has_more": start + len(symbols) < total,
        "warnings": warnings,
    }
