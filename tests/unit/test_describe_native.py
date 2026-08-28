"""classify_target + describe_native: ELF/Mach-O as first-class native targets.

A Linux or macOS native binary is the natural input for radare2, Ghidra and
frida, yet before this it classified as PE and failed create_session with "not
a PE file". These cover the classifier (ELF, thin Mach-O, universal Mach-O, and
the Java .class 0xCAFEBABE collision), the stdlib-only fact reader for each
container, and the session wiring -- including that a native session is still
refused by the PE-only tools through require_pe.
"""

from __future__ import annotations

import glob
import hashlib
import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.models import TargetKind, TargetMismatch
from headless_re_mcp.core.session import (
    SessionRegistry,
    _go_build_info,
    classify_target,
    describe_native,
)


def _elf64_le() -> bytes:
    # 0x7fELF, EI_CLASS=2 (64), EI_DATA=1 (LE); e_type=EXEC, e_machine=x86-64.
    return (
        b"\x7fELF"
        + bytes([2, 1, 1])
        + b"\x00" * 9
        + (2).to_bytes(2, "little")
        + (62).to_bytes(2, "little")
    )


def _elf32_be() -> bytes:
    # EI_CLASS=1 (32), EI_DATA=2 (BE); e_type=DYN, e_machine=arm.
    return (
        b"\x7fELF"
        + bytes([1, 2, 1])
        + b"\x00" * 9
        + (3).to_bytes(2, "big")
        + (40).to_bytes(2, "big")
    )


def _macho64_le() -> bytes:
    # MH_MAGIC_64 little-endian; cputype x86_64, filetype MH_EXECUTE.
    return (
        b"\xcf\xfa\xed\xfe"
        + (0x01000007).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (2).to_bytes(4, "little")
    )


def _macho64_full(filetype: int, flags: int, load_cmds: bytes = b"", ncmds: int = 0) -> bytes:
    # 64-bit little-endian mach_header_64 followed by its load commands.
    return (
        b"\xcf\xfa\xed\xfe"
        + (0x01000007).to_bytes(4, "little")  # cputype x86_64
        + (0).to_bytes(4, "little")  # cpusubtype
        + filetype.to_bytes(4, "little")
        + ncmds.to_bytes(4, "little")
        + len(load_cmds).to_bytes(4, "little")  # sizeofcmds
        + flags.to_bytes(4, "little")
        + (0).to_bytes(4, "little")  # reserved
        + load_cmds
    )


def _lc_load_dylib(name: str, *, cmd_kind: int = 0x0C) -> bytes:
    # dylib_command: LC_LOAD_DYLIB by default; cmd_kind selects the weak
    # (0x80000018) or reexport (0x8000001F) variant of the same layout.
    raw = name.encode() + b"\x00"
    total = (24 + len(raw) + 3) & ~3  # dylib_command struct is 24 bytes, then the name
    cmd = bytearray(total)
    cmd[0:4] = cmd_kind.to_bytes(4, "little")
    cmd[4:8] = total.to_bytes(4, "little")  # cmdsize
    cmd[8:12] = (24).to_bytes(4, "little")  # name offset
    cmd[24 : 24 + len(raw)] = raw
    return bytes(cmd)


def _lc_load_dylinker(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    total = (12 + len(raw) + 3) & ~3  # cmd, cmdsize, name offset (12), then the path
    cmd = bytearray(total)
    cmd[0:4] = (0x0E).to_bytes(4, "little")  # LC_LOAD_DYLINKER
    cmd[4:8] = total.to_bytes(4, "little")
    cmd[8:12] = (12).to_bytes(4, "little")  # name offset
    cmd[12 : 12 + len(raw)] = raw
    return bytes(cmd)


def _lc_rpath(path: str, *, name_offset: int = 12) -> bytes:
    raw = path.encode() + b"\x00"
    total = (12 + len(raw) + 7) & ~7  # rpath_command is an lc_str like the dylinker's
    cmd = bytearray(total)
    cmd[0:4] = (0x8000001C).to_bytes(4, "little")  # LC_RPATH
    cmd[4:8] = total.to_bytes(4, "little")
    cmd[8:12] = name_offset.to_bytes(4, "little")
    cmd[12 : 12 + len(raw)] = raw
    return bytes(cmd)


def _lc_build_version(
    platform: int,
    minos: int,
    sdk: int,
    tools: tuple[tuple[int, int], ...] = (),
    *,
    declared_ntools: int | None = None,
) -> bytes:
    # build_version_command, optionally with trailing build_tool_version
    # entries (tool id, nibble-packed version). ``declared_ntools`` lets a test
    # lie about the count without laying down the entries.
    total = 24 + 8 * len(tools)
    cmd = bytearray(total)
    cmd[0:4] = (0x32).to_bytes(4, "little")  # LC_BUILD_VERSION
    cmd[4:8] = total.to_bytes(4, "little")
    cmd[8:12] = platform.to_bytes(4, "little")
    cmd[12:16] = minos.to_bytes(4, "little")
    cmd[16:20] = sdk.to_bytes(4, "little")
    ntools = declared_ntools if declared_ntools is not None else len(tools)
    cmd[20:24] = ntools.to_bytes(4, "little")
    for index, (tool_id, tool_version) in enumerate(tools):
        base = 24 + index * 8
        cmd[base : base + 4] = tool_id.to_bytes(4, "little")
        cmd[base + 4 : base + 8] = tool_version.to_bytes(4, "little")
    return bytes(cmd)


def _lc_version_min(kind: int, version: int, sdk: int) -> bytes:
    # version_min_command: the command kind itself names the platform.
    cmd = bytearray(16)
    cmd[0:4] = kind.to_bytes(4, "little")
    cmd[4:8] = (16).to_bytes(4, "little")
    cmd[8:12] = version.to_bytes(4, "little")
    cmd[12:16] = sdk.to_bytes(4, "little")
    return bytes(cmd)


def _lc_filler(size: int) -> bytes:
    # A load command the reader does not recognise, used to push later commands
    # past the header window so the streamed read is what reaches them.
    cmd = bytearray(size)
    cmd[0:4] = (0x7FFFFFFF).to_bytes(4, "little")
    cmd[4:8] = size.to_bytes(4, "little")
    return bytes(cmd)


def _lc_id_dylib(name: str) -> bytes:
    raw = name.encode() + b"\x00"
    total = (24 + len(raw) + 3) & ~3  # dylib_command is 24 bytes, then the name
    cmd = bytearray(total)
    cmd[0:4] = (0x0D).to_bytes(4, "little")  # LC_ID_DYLIB
    cmd[4:8] = total.to_bytes(4, "little")
    cmd[8:12] = (24).to_bytes(4, "little")  # name offset
    cmd[24 : 24 + len(raw)] = raw
    return bytes(cmd)


def _lc_uuid_bytes(raw16: bytes) -> bytes:
    return (0x1B).to_bytes(4, "little") + (24).to_bytes(4, "little") + raw16


def _lc_uuid() -> bytes:
    return _lc_uuid_bytes(b"\x00" * 16)


def _lc_symtab(stroff: int, strsize: int, *, symoff: int = 0, nsyms: int = 0) -> bytes:
    # LC_SYMTAB: symoff/nsyms (the symbol table) then stroff/strsize (its names).
    return (
        (0x02).to_bytes(4, "little")
        + (24).to_bytes(4, "little")
        + symoff.to_bytes(4, "little")
        + nsyms.to_bytes(4, "little")
        + stroff.to_bytes(4, "little")
        + strsize.to_bytes(4, "little")
    )


# Mach-O nlist n_type bits: N_EXT marks an external symbol; the type nibble is
# N_SECT for one defined in a section here and N_UNDF for an import.
_N_EXT, _N_SECT, _N_UNDF = 0x01, 0x0E, 0x00


def _macho64_with_symbols(
    symbols: list[tuple[str, int, int]], *, nsyms: int | None = None
) -> bytes:
    """A 64-bit Mach-O carrying an LC_SYMTAB of the given nlist entries.

    Each symbol is ``(name, n_type, n_sect)``; the reader exports those that are
    external (N_EXT) and defined in a section (N_SECT). An empty name forces a
    zero n_strx (a real "no name" symbol). The nlist array and string table are
    laid out right after the single load command, so symoff/stroff address them
    directly. ``nsyms`` overrides the declared symbol count for the lying-count
    case.
    """
    strtab = bytearray(b"\x00")
    nlists = bytearray()
    for name, n_type, n_sect in symbols:
        if name == "":
            strx = 0
        else:
            strx = len(strtab)
            strtab += name.encode() + b"\x00"
        nlists += struct.pack("<IBBHQ", strx, n_type, n_sect, 0, 0)
    cmds_len = 24  # one LC_SYMTAB command
    symoff = 32 + cmds_len
    stroff = symoff + len(nlists)
    declared = nsyms if nsyms is not None else len(symbols)
    cmds = _lc_symtab(stroff, len(strtab), symoff=symoff, nsyms=declared)
    return (
        _macho64_full(filetype=6, flags=0x4, load_cmds=cmds, ncmds=1)
        + bytes(nlists)
        + bytes(strtab)
    )


def _lc_encryption_info(
    cryptid: int, cmd: int = 0x2C, cryptoff: int = 0x1000, cryptsize: int = 0x1000
) -> bytes:
    # LC_ENCRYPTION_INFO(_64): cryptoff/cryptsize then cryptid (+ pad for _64).
    return (
        cmd.to_bytes(4, "little")
        + (24).to_bytes(4, "little")
        + cryptoff.to_bytes(4, "little")
        + cryptsize.to_bytes(4, "little")
        + cryptid.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
    )


def _lc_main(entryoff: int) -> bytes:
    # LC_MAIN: entry point as a file offset of main(), plus an initial stack size.
    return (
        (0x80000028).to_bytes(4, "little")
        + (24).to_bytes(4, "little")
        + entryoff.to_bytes(8, "little")
        + (0).to_bytes(8, "little")
    )


def _lc_segment64(vmaddr: int, fileoff: int, filesize: int, *, initprot: int = 0) -> bytes:
    cmd = bytearray(72)
    cmd[0:4] = (0x19).to_bytes(4, "little")  # LC_SEGMENT_64
    cmd[4:8] = (72).to_bytes(4, "little")
    cmd[8:24] = b"__TEXT".ljust(16, b"\x00")
    cmd[24:32] = vmaddr.to_bytes(8, "little")
    cmd[32:40] = (0x1000).to_bytes(8, "little")  # vmsize
    cmd[40:48] = fileoff.to_bytes(8, "little")
    cmd[48:56] = filesize.to_bytes(8, "little")
    cmd[60:64] = initprot.to_bytes(4, "little")
    return bytes(cmd)


def _lc_segment32(vmaddr: int, fileoff: int, filesize: int, *, initprot: int = 0) -> bytes:
    cmd = bytearray(56)
    cmd[0:4] = (0x01).to_bytes(4, "little")  # LC_SEGMENT
    cmd[4:8] = (56).to_bytes(4, "little")
    cmd[8:24] = b"__TEXT".ljust(16, b"\x00")
    cmd[24:28] = vmaddr.to_bytes(4, "little")
    cmd[28:32] = (0x1000).to_bytes(4, "little")  # vmsize
    cmd[32:36] = fileoff.to_bytes(4, "little")
    cmd[36:40] = filesize.to_bytes(4, "little")
    cmd[44:48] = initprot.to_bytes(4, "little")
    return bytes(cmd)


def _lc_segment64_with_sections(
    sections: list[tuple[int, int]], *, nsects: int | None = None
) -> bytes:
    """An LC_SEGMENT_64 whose section_64 headers carry the given (flags, size).

    Only the fields the init walk reads (the u64 size and the u32 flags whose
    low byte is the section type) are populated; names and offsets stay zero,
    which the reader must not care about. ``nsects`` overrides the declared
    section count for the lying-count case.
    """
    total = 72 + 80 * len(sections)
    cmd = bytearray(72)
    cmd[0:4] = (0x19).to_bytes(4, "little")  # LC_SEGMENT_64
    cmd[4:8] = total.to_bytes(4, "little")
    cmd[8:24] = b"__DATA".ljust(16, b"\x00")
    declared = nsects if nsects is not None else len(sections)
    cmd[64:68] = declared.to_bytes(4, "little")
    body = bytearray()
    for flags, size in sections:
        sect = bytearray(80)
        sect[40:48] = size.to_bytes(8, "little")
        sect[64:68] = flags.to_bytes(4, "little")
        body += sect
    return bytes(cmd) + bytes(body)


def _lc_segment32_with_sections(sections: list[tuple[int, int]]) -> bytes:
    """The 32-bit twin: 68-byte section headers with u32 sizes at +36."""
    total = 56 + 68 * len(sections)
    cmd = bytearray(56)
    cmd[0:4] = (0x01).to_bytes(4, "little")  # LC_SEGMENT
    cmd[4:8] = total.to_bytes(4, "little")
    cmd[8:24] = b"__DATA".ljust(16, b"\x00")
    cmd[48:52] = len(sections).to_bytes(4, "little")
    body = bytearray()
    for flags, size in sections:
        sect = bytearray(68)
        sect[36:40] = size.to_bytes(4, "little")
        sect[56:60] = flags.to_bytes(4, "little")
        body += sect
    return bytes(cmd) + bytes(body)


def _macho32_full(filetype: int, flags: int, load_cmds: bytes = b"", ncmds: int = 0) -> bytes:
    # 32-bit little-endian mach_header (28 bytes, no reserved field).
    return (
        b"\xce\xfa\xed\xfe"
        + (7).to_bytes(4, "little")  # cputype x86
        + (3).to_bytes(4, "little")  # cpusubtype
        + filetype.to_bytes(4, "little")
        + ncmds.to_bytes(4, "little")
        + len(load_cmds).to_bytes(4, "little")
        + flags.to_bytes(4, "little")
        + load_cmds
    )


def _macho_fat(*cputypes: int) -> bytes:
    header = b"\xca\xfe\xba\xbe" + len(cputypes).to_bytes(4, "big")
    for cputype in cputypes:
        header += cputype.to_bytes(4, "big") + b"\x00" * 16
    return header


def _macho_fat_with_slices(slices: list[tuple[int, bytes]]) -> bytes:
    """A universal binary whose fat_arch rows point at real thin payloads.

    Each entry is (cputype, thin Mach-O bytes); the big-endian fat_arch rows
    carry genuine offsets and sizes, with slices laid out back to back after
    the header the way lipo emits them.
    """
    header = bytearray(b"\xca\xfe\xba\xbe" + len(slices).to_bytes(4, "big"))
    offset = 8 + 20 * len(slices)
    body = bytearray()
    for cputype, blob in slices:
        header += cputype.to_bytes(4, "big") + b"\x00" * 4
        header += offset.to_bytes(4, "big") + len(blob).to_bytes(4, "big")
        header += b"\x00" * 4  # align
        body += blob
        offset += len(blob)
    return bytes(header) + bytes(body)


def _retyped_macho(blob: bytes, cputype: int) -> bytes:
    """The same thin Mach-O with its little-endian cputype field rewritten."""
    return blob[:4] + cputype.to_bytes(4, "little") + blob[8:]


def _java_class() -> bytes:
    # 0xCAFEBABE then minor=0, major=52 (Java 8), then a constant-pool count.
    return b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (52).to_bytes(2, "big") + b"\x00" * 8


def _phdr64(
    p_type: int, p_offset: int = 0, p_filesz: int = 0, p_vaddr: int = 0, p_flags: int = 0
) -> bytes:
    entry = bytearray(56)
    entry[0:4] = p_type.to_bytes(4, "little")
    entry[4:8] = p_flags.to_bytes(4, "little")  # p_flags follows p_type in ELF64
    entry[8:16] = p_offset.to_bytes(8, "little")
    entry[16:24] = p_vaddr.to_bytes(8, "little")
    entry[32:40] = p_filesz.to_bytes(8, "little")
    return bytes(entry)


def _shdr64(sh_type: int) -> bytes:
    entry = bytearray(64)
    entry[4:8] = sh_type.to_bytes(4, "little")
    return bytes(entry)


def _ehdr64(
    e_type: int, *, phoff: int, phnum: int, shoff: int, shnum: int, entry: int = 0
) -> bytes:
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1  # 64-bit, little-endian, version 1
    ehdr[16:18] = e_type.to_bytes(2, "little")
    ehdr[18:20] = (62).to_bytes(2, "little")  # x86-64
    ehdr[24:32] = entry.to_bytes(8, "little")
    ehdr[32:40] = phoff.to_bytes(8, "little")
    ehdr[40:48] = shoff.to_bytes(8, "little")
    ehdr[54:56] = (56).to_bytes(2, "little")  # e_phentsize
    ehdr[56:58] = phnum.to_bytes(2, "little")
    ehdr[58:60] = (64).to_bytes(2, "little")  # e_shentsize
    ehdr[60:62] = shnum.to_bytes(2, "little")
    return bytes(ehdr)


def _elf64_dynamic_pie() -> bytes:
    interp = b"/lib64/ld.so.1\x00"
    # DT_FLAGS_1 carrying DF_1_PIE, then DT_NULL to end the array.
    dyn = (
        (0x6FFFFFFB).to_bytes(8, "little")
        + (0x08000000).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
    )
    ph_off = 64
    blob_off = ph_off + 56 * 2
    interp_off = blob_off
    dyn_off = interp_off + len(interp)
    program = _phdr64(3, interp_off, len(interp)) + _phdr64(2, dyn_off, len(dyn))
    ehdr = _ehdr64(3, phoff=ph_off, phnum=2, shoff=0, shnum=0)  # ET_DYN
    return ehdr + program + interp + dyn


def _elf64_dynamic_with_needed() -> bytes:
    """A dynamic ELF whose DT_NEEDED names two shared libraries.

    A PT_LOAD segment with vaddr == offset == 0 makes the DT_STRTAB virtual
    address map straight to its file offset, so the reader resolves the name
    offsets the same way it does on a real image.
    """
    strtab = b"\x00libc.so.6\x00libm.so.6\x00"  # names at offsets 1 and 11
    dyn = b"".join(
        tag.to_bytes(8, "little") + val.to_bytes(8, "little")
        for tag, val in (
            (1, 1),  # DT_NEEDED -> "libc.so.6"
            (1, 11),  # DT_NEEDED -> "libm.so.6"
            (5, 176),  # DT_STRTAB (vaddr == file offset of the string table)
            (10, len(strtab)),  # DT_STRSZ
            (0, 0),  # DT_NULL
        )
    )
    ph_off = 64
    strtab_off = ph_off + 56 * 2  # == 176, matching DT_STRTAB above
    dyn_off = strtab_off + len(strtab)
    program = _phdr64(1, p_offset=0, p_filesz=0x10000, p_vaddr=0) + _phdr64(  # PT_LOAD
        2, dyn_off, len(dyn)  # PT_DYNAMIC
    )
    ehdr = _ehdr64(3, phoff=ph_off, phnum=2, shoff=0, shnum=0)  # ET_DYN
    return ehdr + program + strtab + dyn


def _elf64_shared_with_soname_and_build_id() -> bytes:
    """A shared object that declares a soname and carries a GNU build-id note."""
    strtab = b"\x00libc.so.6\x00libmylib.so.1\x00"  # needed at 1, soname at 11
    build_id = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])
    note = (
        (4).to_bytes(4, "little")  # namesz "GNU\0"
        + len(build_id).to_bytes(4, "little")  # descsz
        + (3).to_bytes(4, "little")  # NT_GNU_BUILD_ID
        + b"GNU\x00"
        + build_id
    )
    ph_off = 64
    strtab_off = ph_off + 56 * 3  # three program headers precede the blobs
    note_off = strtab_off + len(strtab)
    dyn = b"".join(
        tag.to_bytes(8, "little") + val.to_bytes(8, "little")
        for tag, val in (
            (1, 1),  # DT_NEEDED -> "libc.so.6"
            (14, 11),  # DT_SONAME -> "libmylib.so.1"
            (5, strtab_off),  # DT_STRTAB (vaddr == file offset)
            (10, len(strtab)),  # DT_STRSZ
            (0, 0),  # DT_NULL
        )
    )
    dyn_off = note_off + len(note)
    program = (
        _phdr64(1, p_offset=0, p_filesz=0x10000, p_vaddr=0)  # PT_LOAD, vaddr==offset
        + _phdr64(2, dyn_off, len(dyn))  # PT_DYNAMIC
        + _phdr64(4, note_off, len(note))  # PT_NOTE
    )
    ehdr = _ehdr64(3, phoff=ph_off, phnum=3, shoff=0, shnum=0)  # ET_DYN
    return ehdr + program + strtab + note + dyn


def _elf_note(ntype: int, name: bytes, desc: bytes) -> bytes:
    namesz = len(name) + 1  # the reader counts the trailing NUL in namesz
    padded_name = (name + b"\x00").ljust((namesz + 3) & ~3, b"\x00")
    padded_desc = desc.ljust((len(desc) + 3) & ~3, b"\x00")
    return (
        namesz.to_bytes(4, "little")
        + len(desc).to_bytes(4, "little")
        + ntype.to_bytes(4, "little")
        + padded_name
        + padded_desc
    )


def _abi_note(os_id: int, major: int, minor: int, sub: int) -> bytes:
    # NT_GNU_ABI_TAG (type 1): os id then the min kernel major/minor/subminor.
    desc = b"".join(v.to_bytes(4, "little") for v in (os_id, major, minor, sub))
    return _elf_note(1, b"GNU", desc)


def _elf64_with_notes(note: bytes) -> bytes:
    """An ELF whose single PT_NOTE segment carries ``note`` (read by file offset)."""
    ph_off = 64
    note_off = ph_off + 56  # one program header precedes the note bytes
    program = _phdr64(4, note_off, len(note))  # PT_NOTE
    ehdr = _ehdr64(3, phoff=ph_off, phnum=1, shoff=0, shnum=0)
    return ehdr + program + note


def _elf64_static_with_symtab() -> bytes:
    ph_off = 64
    sh_off = ph_off + 56  # one program header
    program = _phdr64(1)  # PT_LOAD, no dynamic/interp -> static
    sections = _shdr64(0) + _shdr64(2)  # SHT_NULL + SHT_SYMTAB -> not stripped
    ehdr = _ehdr64(2, phoff=ph_off, phnum=1, shoff=sh_off, shnum=2)  # ET_EXEC
    return ehdr + program + sections


# Symbol binding / type / special section index constants for the .dynsym builder.
_STB_LOCAL, _STB_GLOBAL, _STB_WEAK = 0, 1, 2
_STT_NOTYPE, _STT_OBJECT, _STT_FUNC = 0, 1, 2
_SHN_UNDEF, _SHN_ABS = 0, 0xFFF1


def _shdr64_full(
    sh_type: int,
    *,
    sh_offset: int = 0,
    sh_size: int = 0,
    sh_link: int = 0,
    sh_entsize: int = 0,
) -> bytes:
    entry = bytearray(64)
    entry[4:8] = sh_type.to_bytes(4, "little")
    entry[24:32] = sh_offset.to_bytes(8, "little")
    entry[32:40] = sh_size.to_bytes(8, "little")
    entry[40:44] = sh_link.to_bytes(4, "little")
    entry[56:64] = sh_entsize.to_bytes(8, "little")
    return bytes(entry)


def _sym64(name_off: int, bind: int, typ: int, shndx: int) -> bytes:
    entry = bytearray(24)
    entry[0:4] = name_off.to_bytes(4, "little")
    entry[4] = (bind << 4) | (typ & 0xF)
    entry[6:8] = shndx.to_bytes(2, "little")
    return bytes(entry)


def _elf64_with_dynsym(
    symbols: list[tuple[str, int, int, int]], *, dynsym_size: int | None = None
) -> bytes:
    """A section-header-only ELF carrying a .dynsym and its linked .dynstr.

    Each symbol is ``(name, bind, type, shndx)``; the reader selects the
    exported ones (defined section index, GLOBAL/WEAK binding) exactly as it
    does on a real image read through readelf --dyn-syms. ``dynsym_size`` forces
    the section's declared byte size (defaulting to the real one) so a lying
    size can be exercised. Laid out ehdr | .dynstr | .dynsym | section headers,
    with a leading null symbol as .dynsym always carries.
    """
    dynstr = bytearray(b"\x00")
    offsets: list[int] = []
    for name, _bind, _typ, _shndx in symbols:
        offsets.append(len(dynstr))
        dynstr += name.encode("utf-8") + b"\x00"
    syms = bytearray(_sym64(0, 0, 0, 0))  # index 0: the null symbol
    for (_name, bind, typ, shndx), off in zip(symbols, offsets, strict=True):
        syms += _sym64(off, bind, typ, shndx)

    ehdr_len = 64
    dynstr_off = ehdr_len
    dynsym_off = dynstr_off + len(dynstr)
    sh_off = dynsym_off + len(syms)
    declared = dynsym_size if dynsym_size is not None else len(syms)
    sections = (
        _shdr64_full(0)  # SHT_NULL
        + _shdr64_full(
            11, sh_offset=dynsym_off, sh_size=declared, sh_link=2, sh_entsize=24
        )  # SHT_DYNSYM, linked to section 2 (.dynstr)
        + _shdr64_full(3, sh_offset=dynstr_off, sh_size=len(dynstr))  # SHT_STRTAB
    )
    ehdr = _ehdr64(3, phoff=0, phnum=0, shoff=sh_off, shnum=3)  # ET_DYN
    return ehdr + bytes(dynstr) + bytes(syms) + sections


# PT_GNU_STACK/PT_GNU_RELRO and the PF_X permission bit -- the segments that
# carry the NX and RELRO mitigations. PF_R|PF_W is a non-executable stack.
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_RW = 0x6
_PF_RWX = 0x7


def _elf64_with_gnu_stack(*, executable: bool) -> bytes:
    """A minimal ELF whose only program header is a PT_GNU_STACK.

    The stack's PF_X bit is the whole NX signal: RW-only means NX on, RWX means
    NX off. No PT_GNU_RELRO, so RELRO reads as none.
    """
    program = _phdr64(_PT_GNU_STACK, p_flags=_PF_RWX if executable else _PF_RW)
    ehdr = _ehdr64(2, phoff=64, phnum=1, shoff=0, shnum=0)  # ET_EXEC
    return ehdr + program


def _elf64_relro(
    *, bind_now_tag: bool = False, flags: int = 0, flags_1: int = 0, textrel_tag: bool = False
) -> bytes:
    """A dynamic ELF carrying PT_GNU_RELRO plus a controllable dynamic section.

    RELRO is partial with only the segment present; it upgrades to full when the
    dynamic section forces eager binding -- via a DT_BIND_NOW tag, DF_BIND_NOW in
    DT_FLAGS, or DF_1_NOW in DT_FLAGS_1 -- so each of the three markers is
    exercised through the same builder. The same dynamic array also carries the
    text-relocation markers (a DT_TEXTREL tag, or DF_TEXTREL in DT_FLAGS).
    """
    entries: list[tuple[int, int]] = []
    if bind_now_tag:
        entries.append((24, 0))  # DT_BIND_NOW
    if textrel_tag:
        entries.append((22, 0))  # DT_TEXTREL
    if flags:
        entries.append((30, flags))  # DT_FLAGS
    if flags_1:
        entries.append((0x6FFFFFFB, flags_1))  # DT_FLAGS_1
    entries.append((0, 0))  # DT_NULL
    dyn = b"".join(tag.to_bytes(8, "little") + val.to_bytes(8, "little") for tag, val in entries)
    ph_off = 64
    dyn_off = ph_off + 56 * 3  # three program headers precede the dynamic array
    program = (
        _phdr64(2, dyn_off, len(dyn))  # PT_DYNAMIC
        + _phdr64(_PT_GNU_RELRO)
        + _phdr64(_PT_GNU_STACK, p_flags=_PF_RW)  # non-exec stack -> nx on
    )
    ehdr = _ehdr64(3, phoff=ph_off, phnum=3, shoff=0, shnum=0)  # ET_DYN
    return ehdr + program + dyn


def _elf64_dynamic_with_strtab(
    strtab: bytes,
    *,
    rpath: int | None = None,
    runpath: int | None = None,
    verneed: bytes | None = None,
    verneed_num: int = 1,
    verdef: bytes | None = None,
    verdef_num: int = 1,
    extra_tags: list[tuple[int, int]] | None = None,
) -> bytes:
    """A dynamic ELF whose DT_STRTAB points at ``strtab``.

    A PT_LOAD with vaddr == offset == 0 makes DT_STRTAB's virtual address map
    straight to its file offset, the same trick the DT_NEEDED builder uses, so
    the reader resolves the string table exactly as it does on a real image.
    ``rpath``/``runpath`` add a DT_RPATH/DT_RUNPATH tag whose value is the given
    string-table offset. ``verneed`` appends a .gnu.version_r blob behind the
    dynamic array and points DT_VERNEED at it, declaring ``verneed_num``
    records; ``verdef`` appends a .gnu.version_d blob behind that and points
    DT_VERDEF at it, declaring ``verdef_num`` records. ``extra_tags`` are raw
    ``(tag, value)`` rows prepended verbatim (DT_INIT and friends).
    """
    entries: list[tuple[int, int]] = list(extra_tags or [])
    if rpath is not None:
        entries.append((15, rpath))  # DT_RPATH
    if runpath is not None:
        entries.append((29, runpath))  # DT_RUNPATH
    entries += [
        (5, 176),  # DT_STRTAB (vaddr == file offset of the string table)
        (10, len(strtab)),  # DT_STRSZ
    ]
    ph_off = 64
    strtab_off = ph_off + 56 * 2  # == 176, matching DT_STRTAB above
    dyn_off = strtab_off + len(strtab)
    # The dynamic array size is fixed once every row is known, so the version
    # blobs that sit behind it get stable file offsets. Count the rows added
    # below (2 per present version tag) plus the trailing DT_NULL, then place
    # each blob in turn: with the vaddr == offset PT_LOAD, each file offset is
    # its virtual address too, so DT_VERNEED/DT_VERDEF can point straight at it.
    row_count = len(entries) + (2 if verneed is not None else 0)
    row_count += (2 if verdef is not None else 0) + 1
    blob_base = dyn_off + row_count * 16
    if verneed is not None:
        entries += [(0x6FFFFFFE, blob_base), (0x6FFFFFFF, verneed_num)]
    if verdef is not None:
        vd_off = blob_base + (len(verneed) if verneed is not None else 0)
        entries += [(0x6FFFFFFC, vd_off), (0x6FFFFFFD, verdef_num)]
    entries.append((0, 0))  # DT_NULL
    dyn = b"".join(
        tag.to_bytes(8, "little") + val.to_bytes(8, "little") for tag, val in entries
    )
    program = _phdr64(1, p_offset=0, p_filesz=0x10000, p_vaddr=0) + _phdr64(2, dyn_off, len(dyn))
    ehdr = _ehdr64(3, phoff=ph_off, phnum=2, shoff=0, shnum=0)  # ET_DYN
    return ehdr + program + strtab + dyn + (verneed or b"") + (verdef or b"")


def _verneed_blob(entries: list[tuple[int, list[int]]]) -> bytes:
    """A .gnu.version_r blob: one Verneed record per ``(file_off, name_offs)``.

    ``file_off`` names the library and each ``name_offs`` entry one required
    version tag, all as offsets into the dynamic string table. Records and
    their Vernaux chains are laid out contiguously with the standard 16-byte
    hops, the way ld emits them.
    """
    out = bytearray()
    for index, (file_off, name_offs) in enumerate(entries):
        aux = bytearray()
        for j, name_off in enumerate(name_offs):
            vna_next = 16 if j + 1 < len(name_offs) else 0
            # vna_hash, vna_flags, vna_other, vna_name, vna_next
            aux += struct.pack("<IHHII", 0, 0, 0, name_off, vna_next)
        vn_next = 16 + len(aux) if index + 1 < len(entries) else 0
        # vn_version, vn_cnt, vn_file, vn_aux, vn_next
        out += struct.pack("<HHIII", 1, len(name_offs), file_off, 16, vn_next) + bytes(aux)
    return bytes(out)


def _verdef_blob(entries: list[tuple[int, list[int], int]]) -> bytes:
    """A .gnu.version_d blob: one Verdef record per ``(name_off, parents, flags)``.

    ``name_off`` is the version node's own name and each ``parents`` entry a
    parent version it inherits, all as offsets into the dynamic string table;
    ``flags`` carries VER_FLG_BASE (1) for the node that names the object. The
    first Verdaux is the node's own name and the rest its parents, laid out
    contiguously with the standard 20-byte record / 8-byte aux hops ld emits.
    """
    out = bytearray()
    for index, (name_off, parents, flags) in enumerate(entries):
        aux_offs = [name_off, *parents]
        aux = bytearray()
        for j, off in enumerate(aux_offs):
            vda_next = 8 if j + 1 < len(aux_offs) else 0
            aux += struct.pack("<II", off, vda_next)  # vda_name, vda_next
        vd_next = 20 + len(aux) if index + 1 < len(entries) else 0
        # vd_version, vd_flags, vd_ndx, vd_cnt, vd_hash, vd_aux, vd_next
        out += struct.pack(
            "<HHHHIII", 1, flags, index + 1, len(aux_offs), 0, 20, vd_next
        ) + bytes(aux)
    return bytes(out)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_reads_a_real_system_elf() -> None:
    candidates = ["/bin/ls", "/usr/bin/python3", *glob.glob("/lib/*/libc.so*")]
    sample = next((c for c in candidates if Path(c).is_file()), None)
    if sample is None:
        pytest.skip("no system ELF available (skip != pass)")
    path = Path(sample).resolve()
    assert classify_target(str(path)) is TargetKind.NATIVE
    facts = describe_native(path)["native"]
    assert facts["format"] == "elf"
    assert facts["bits"] in (32, 64)
    assert facts["arch"]


def test_elf64_little_endian_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_le())
    assert classify_target(str(path)) is TargetKind.NATIVE
    assert describe_native(path)["native"] == {
        "format": "elf",
        "bits": 64,
        "endianness": "little",
        "type": "exec",
        "arch": "x86-64",
        "urls": [],
        "url_count": 0,
        "cleartext_url_count": 0,
    }


def test_elf32_big_endian_arm_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf32_be())
    facts = describe_native(path)["native"]
    assert facts["bits"] == 32
    assert facts["endianness"] == "big"
    assert facts["type"] == "dyn"
    assert facts["arch"] == "arm"
    # A header-only ELF has no program/section tables to read, so the triage
    # facts stay absent rather than being guessed.
    assert "linking" not in facts
    assert "stripped" not in facts


def test_dynamic_pie_facts_from_program_headers(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_dynamic_pie())
    facts = describe_native(path)["native"]
    assert facts["type"] == "dyn"
    assert facts["linking"] == "dynamic"
    assert facts["pie"] is True  # DT_FLAGS_1 carries DF_1_PIE
    assert facts["interpreter"] == "/lib64/ld.so.1"
    # This image carries neither PT_GNU_STACK nor PT_GNU_RELRO, so the
    # mitigations read as off/none -- the same call r2 makes on such a binary.
    assert facts["nx"] is False
    assert facts["relro"] == "none"


def test_dynamic_needed_libraries_from_the_dynamic_string_table(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_needed())
    facts = describe_native(path)["native"]
    assert facts["linking"] == "dynamic"
    # The ELF analogue of Mach-O's dylibs: DT_NEEDED resolved through DT_STRTAB.
    assert facts["needed"] == ["libc.so.6", "libm.so.6"]
    # This string table names no stack-guard symbol, so canary reads False.
    assert facts["canary"] is False


def test_stack_canary_detected_from_the_dynamic_symbol_names(tmp_path: Path) -> None:
    # A -fstack-protector build references a guard symbol; its name lands in the
    # dynamic string table, which is exactly what checksec greps and r2 reports.
    guarded = describe_native(
        _write(tmp_path, "y.bin", _elf64_dynamic_with_strtab(b"\x00puts\x00__stack_chk_fail\x00"))
    )["native"]
    assert guarded["canary"] is True
    unguarded = describe_native(
        _write(tmp_path, "n.bin", _elf64_dynamic_with_strtab(b"\x00puts\x00malloc\x00"))
    )["native"]
    assert unguarded["canary"] is False


def test_runpath_splits_the_colon_separated_search_list(tmp_path: Path) -> None:
    # DT_RUNPATH is one colon-separated string in the dynamic string table; the
    # reader splits it into the list the loader would walk. $ORIGIN tokens are
    # reported verbatim -- expansion is the loader's business, not triage's.
    strtab = b"\x00/opt/lib:$ORIGIN/../lib\x00"
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, runpath=1))
    facts = describe_native(path)["native"]
    assert facts["runpath"] == ["/opt/lib", "$ORIGIN/../lib"]
    assert "rpath" not in facts


def test_rpath_and_runpath_are_reported_separately(tmp_path: Path) -> None:
    # Old-style DT_RPATH and new-style DT_RUNPATH have different loader
    # precedence (before vs after LD_LIBRARY_PATH), so they stay distinct facts.
    strtab = b"\x00/legacy\x00/modern\x00"
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, rpath=1, runpath=9)
    )
    facts = describe_native(path)["native"]
    assert facts["rpath"] == ["/legacy"]
    assert facts["runpath"] == ["/modern"]


def test_no_search_path_tags_leave_the_facts_out(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_needed())
    facts = describe_native(path)["native"]
    assert "rpath" not in facts
    assert "runpath" not in facts


def test_a_search_path_offset_past_the_string_table_stays_out(tmp_path: Path) -> None:
    # A hostile DT_RUNPATH offset beyond the string table cannot be resolved;
    # the fact is omitted rather than guessed or read out of bounds.
    strtab = b"\x00/opt/lib\x00"
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, runpath=len(strtab) + 100)
    )
    facts = describe_native(path)["native"]
    assert "runpath" not in facts


def test_version_needs_report_library_and_version_tags(tmp_path: Path) -> None:
    # DT_VERNEED is the minimum-runtime fact: which version tags of which
    # libraries the loader must satisfy. readelf -V decodes the same chain.
    strtab = b"\x00libc.so.6\x00GLIBC_2.2.5\x00GLIBC_2.34\x00"
    verneed = _verneed_blob([(1, [11, 23])])  # libc.so.6: 2.2.5 then 2.34
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verneed=verneed))
    facts = describe_native(path)["native"]
    assert facts["version_needs"] == [
        {"file": "libc.so.6", "versions": ["GLIBC_2.2.5", "GLIBC_2.34"]}
    ]


def test_version_needs_chain_several_libraries(tmp_path: Path) -> None:
    # One Verneed record per library, linked by vn_next -- the shape ld emits
    # for a binary that imports versioned symbols from more than one library.
    strtab = b"\x00libc.so.6\x00libm.so.6\x00GLIBC_2.35\x00"
    verneed = _verneed_blob([(1, [21]), (11, [21])])
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verneed=verneed, verneed_num=2)
    )
    facts = describe_native(path)["native"]
    assert facts["version_needs"] == [
        {"file": "libc.so.6", "versions": ["GLIBC_2.35"]},
        {"file": "libm.so.6", "versions": ["GLIBC_2.35"]},
    ]


def test_no_verneed_leaves_the_fact_out(tmp_path: Path) -> None:
    # A dynamic binary with no versioned imports (or a static one) has no
    # minimum-runtime chain; the fact is omitted rather than an empty list.
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_needed())
    assert "version_needs" not in describe_native(path)["native"]


def test_a_truncated_verneed_chain_reports_what_parsed(tmp_path: Path) -> None:
    # vn_next pointing past the file is hostile input: the walk keeps the
    # record it already read and stops, rather than raising or looping.
    strtab = b"\x00libc.so.6\x00GLIBC_2.34\x00"
    record = bytearray(_verneed_blob([(1, [11])]))
    record[12:16] = (0x7FFFFFFF).to_bytes(4, "little")  # vn_next -> far past EOF
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_dynamic_with_strtab(strtab, verneed=bytes(record), verneed_num=2),
    )
    facts = describe_native(path)["native"]
    assert facts["version_needs"] == [{"file": "libc.so.6", "versions": ["GLIBC_2.34"]}]


def test_a_verneed_with_a_wrong_revision_is_ignored(tmp_path: Path) -> None:
    # vn_version must be 1 (the only revision ever defined); anything else
    # means the chain is garbage, so no fact is invented from it.
    strtab = b"\x00libc.so.6\x00GLIBC_2.34\x00"
    record = bytearray(_verneed_blob([(1, [11])]))
    record[0:2] = (7).to_bytes(2, "little")
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verneed=bytes(record))
    )
    assert "version_needs" not in describe_native(path)["native"]


def test_a_lying_vernaux_count_stays_bounded(tmp_path: Path) -> None:
    # vn_cnt is attacker-controlled; a huge claim walks at most the capped
    # number of aux records and keeps only the names that resolve.
    strtab = b"\x00libc.so.6\x00GLIBC_2.34\x00"
    record = bytearray(_verneed_blob([(1, [11])]))
    record[2:4] = (0xFFFF).to_bytes(2, "little")  # vn_cnt: 65535 claimed
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verneed=bytes(record))
    )
    facts = describe_native(path)["native"]
    assert facts["version_needs"] == [{"file": "libc.so.6", "versions": ["GLIBC_2.34"]}]


def test_version_defs_report_the_nodes_the_object_provides(tmp_path: Path) -> None:
    # DT_VERDEF is the export-side fact: the version nodes a shared object
    # defines. The first carries VER_FLG_BASE and names the object; a later
    # node may inherit a parent. readelf -V decodes the same section.
    strtab = b"\x00libprobe.so.1\x00PROBE_1.0\x00PROBE_2.0\x00"
    # base(soname)@1, PROBE_1.0@15, PROBE_2.0@25 inheriting PROBE_1.0.
    verdef = _verdef_blob([(1, [], 0x1), (15, [], 0), (25, [15], 0)])
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verdef=verdef, verdef_num=3)
    )
    facts = describe_native(path)["native"]
    assert facts["version_defs"] == [
        {"name": "libprobe.so.1", "base": True, "parents": []},
        {"name": "PROBE_1.0", "base": False, "parents": []},
        {"name": "PROBE_2.0", "base": False, "parents": ["PROBE_1.0"]},
    ]


def test_no_verdef_leaves_the_fact_out(tmp_path: Path) -> None:
    # A binary that defines no version nodes (an ordinary executable, or a
    # library built without a version script) has no Verdef chain; the fact is
    # omitted rather than reported as an empty list.
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_needed())
    assert "version_defs" not in describe_native(path)["native"]


def test_a_truncated_verdef_chain_reports_what_parsed(tmp_path: Path) -> None:
    # vd_next pointing past the file is hostile input: the walk keeps the node
    # it already read and stops, rather than raising or looping.
    strtab = b"\x00libprobe.so.1\x00PROBE_1.0\x00"
    record = bytearray(_verdef_blob([(1, [], 0x1)]))
    record[16:20] = (0x7FFFFFFF).to_bytes(4, "little")  # vd_next -> far past EOF
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_dynamic_with_strtab(strtab, verdef=bytes(record), verdef_num=2),
    )
    facts = describe_native(path)["native"]
    assert facts["version_defs"] == [{"name": "libprobe.so.1", "base": True, "parents": []}]


def test_a_verdef_with_a_wrong_revision_is_ignored(tmp_path: Path) -> None:
    # vd_version must be 1 (the only revision ever defined); anything else
    # means the chain is garbage, so no fact is invented from it.
    strtab = b"\x00libprobe.so.1\x00"
    record = bytearray(_verdef_blob([(1, [], 0x1)]))
    record[0:2] = (7).to_bytes(2, "little")
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verdef=bytes(record))
    )
    assert "version_defs" not in describe_native(path)["native"]


def test_a_lying_verdaux_count_stays_bounded(tmp_path: Path) -> None:
    # vd_cnt is attacker-controlled; a huge claim walks at most the capped
    # number of aux records and keeps only the names that resolve.
    strtab = b"\x00libprobe.so.1\x00"
    record = bytearray(_verdef_blob([(1, [], 0x1)]))
    record[6:8] = (0xFFFF).to_bytes(2, "little")  # vd_cnt: 65535 claimed
    path = _write(
        tmp_path, "a.bin", _elf64_dynamic_with_strtab(strtab, verdef=bytes(record))
    )
    facts = describe_native(path)["native"]
    assert facts["version_defs"] == [{"name": "libprobe.so.1", "base": True, "parents": []}]


def test_init_funcs_report_the_constructor_surface(tmp_path: Path) -> None:
    # The code that runs before the entry point: legacy DT_INIT/DT_FINI plus
    # the three pointer arrays, whose declared byte sizes over the 8-byte
    # pointer width are the entry counts readelf -d derives from the same
    # INIT_ARRAYSZ/FINI_ARRAYSZ/PREINIT_ARRAYSZ tags.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_dynamic_with_strtab(
            b"\x00",
            extra_tags=[
                (12, 0x1000),  # DT_INIT
                (13, 0x2000),  # DT_FINI
                (27, 24),  # DT_INIT_ARRAYSZ: three constructors
                (28, 8),  # DT_FINI_ARRAYSZ: one destructor
                (33, 16),  # DT_PREINIT_ARRAYSZ: two preinit hooks
            ],
        ),
    )
    assert describe_native(path)["native"]["init_funcs"] == {
        "has_init": True,
        "has_fini": True,
        "init_array": 3,
        "fini_array": 1,
        "preinit_array": 2,
    }


def test_no_constructor_tags_read_as_a_zeroed_surface(tmp_path: Path) -> None:
    # A dynamic image with no init/fini tags still answers -- "runs nothing
    # before main" is a real, reassuring fact, not a missing one.
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_strtab(b"\x00"))
    assert describe_native(path)["native"]["init_funcs"] == {
        "has_init": False,
        "has_fini": False,
        "init_array": 0,
        "fini_array": 0,
        "preinit_array": 0,
    }


def test_a_zero_dt_init_is_not_a_constructor(tmp_path: Path) -> None:
    # A DT_INIT whose pointer is null names nothing to run; only a real
    # address counts, so a zeroed tag cannot fake a constructor.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_dynamic_with_strtab(b"\x00", extra_tags=[(12, 0), (27, 12)]),
    )
    facts = describe_native(path)["native"]
    assert facts["init_funcs"]["has_init"] is False
    # 12 bytes is one whole 8-byte pointer: partial trailing entries do not
    # count, exactly as the loader would never call half a pointer.
    assert facts["init_funcs"]["init_array"] == 1


def test_a_lying_init_array_size_stays_bounded(tmp_path: Path) -> None:
    # INIT_ARRAYSZ is attacker-controlled; only the size field is read (no
    # pointer is followed), and the derived count is clamped so a hostile
    # image cannot put a fantastical number in the facts.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_dynamic_with_strtab(b"\x00", extra_tags=[(27, 1 << 40)]),
    )
    assert describe_native(path)["native"]["init_funcs"]["init_array"] == 8192


def test_exported_symbols_lists_defined_global_and_weak(tmp_path: Path) -> None:
    # The export surface: a defined GLOBAL function and a defined WEAK object
    # are exported; an undefined GLOBAL (an import) and a defined LOCAL are
    # not. readelf --dyn-syms / nm -D select the same set.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("exported_add", _STB_GLOBAL, _STT_FUNC, 10),
                ("exported_counter", _STB_WEAK, _STT_OBJECT, 19),
                ("imported_puts", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("local_helper", _STB_LOCAL, _STT_FUNC, 10),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["exported_symbols"] == ["exported_add", "exported_counter"]
    # The same walk splits the undefined GLOBAL to the import side -- the
    # symbol-granular capability list DT_NEEDED only gives per library.
    assert facts["imported_symbols"] == ["imported_puts"]


def test_imported_symbols_list_undefined_globals_and_weaks(tmp_path: Path) -> None:
    # The import surface: undefined GLOBALs and WEAKs are the loader's to
    # resolve; an undefined LOCAL (a linker artifact) is nobody's import, and
    # a fully defined image reports no import fact at all.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("imported_puts", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("imported_hook", _STB_WEAK, _STT_FUNC, _SHN_UNDEF),
                ("local_und", _STB_LOCAL, _STT_NOTYPE, _SHN_UNDEF),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["imported_symbols"] == ["imported_hook", "imported_puts"]
    assert "exported_symbols" not in facts

    defined_only = _write(
        tmp_path,
        "b.bin",
        _elf64_with_dynsym([("exported_add", _STB_GLOBAL, _STT_FUNC, 10)]),
    )
    assert "imported_symbols" not in describe_native(defined_only)["native"]


def test_weak_imports_name_the_optional_capability_subset(tmp_path: Path) -> None:
    # A weakly bound undefined symbol is optional capability the loader leaves
    # null when unresolved -- the ELF pair to a Mach-O weak dylib / PE delay
    # import. It stays in imported_symbols (the full set) and is named apart
    # in weak_imports; a hard undefined GLOBAL is an import but not weak.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("hard_puts", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("weak_pthread_once", _STB_WEAK, _STT_FUNC, _SHN_UNDEF),
                ("weak_gmon_start", _STB_WEAK, _STT_NOTYPE, _SHN_UNDEF),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    # The full import set keeps both bindings...
    assert facts["imported_symbols"] == ["hard_puts", "weak_gmon_start", "weak_pthread_once"]
    # ...and the subset names only the weakly bound ones.
    assert facts["weak_imports"] == ["weak_gmon_start", "weak_pthread_once"]


def test_all_hard_imports_read_an_empty_weak_subset(tmp_path: Path) -> None:
    # A weakly *defined* export is not a weak import: weak_imports is the
    # undefined-and-weak intersection, so an image whose only undefined
    # symbols are hard GLOBALs reports an empty (but present) subset.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("hard_puts", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("weak_export", _STB_WEAK, _STT_OBJECT, 10),  # defined, so an export
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["imported_symbols"] == ["hard_puts"]
    assert facts["weak_imports"] == []
    assert facts["exported_symbols"] == ["weak_export"]


def test_fortify_source_names_the_chk_wrappers(tmp_path: Path) -> None:
    # A -D_FORTIFY_SOURCE build imports libc's fortified wrappers, each named
    # __<func>_chk; their presence is the checksec FORTIFY signal, and the
    # count is how many distinct wrappers are used.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("__printf_chk", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("__memcpy_chk", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("puts", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["fortify_source"] is True
    # Sorted, and only the fortified wrappers -- the plain libc import is out.
    assert facts["fortified_functions"] == ["__memcpy_chk", "__printf_chk"]


def test_an_unfortified_binary_reads_fortify_false(tmp_path: Path) -> None:
    # Imports but no __*_chk wrapper: a real "built without FORTIFY" answer,
    # present (not omitted) so the posture is definitively negative.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym([("puts", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF)]),
    )
    facts = describe_native(path)["native"]
    assert facts["fortify_source"] is False
    assert facts["fortified_functions"] == []


def test_a_user_symbol_ending_in_chk_is_not_a_fortify_wrapper(tmp_path: Path) -> None:
    # The wrappers are all __<func>_chk; a user import that merely ends in
    # _chk (no __ prefix) must not be miscounted as FORTIFY, and the canary's
    # own _fail/_guard symbols are not _chk wrappers either.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("validate_chk", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
                ("__stack_chk_fail", _STB_GLOBAL, _STT_FUNC, _SHN_UNDEF),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["fortify_source"] is False
    assert facts["fortified_functions"] == []


def test_no_dynsym_leaves_the_weak_import_fact_out_too(tmp_path: Path) -> None:
    # weak_imports rides with imported_symbols: no .dynsym, no import fact of
    # any kind, so the subset is absent rather than an empty list.
    path = _write(tmp_path, "a.bin", _elf64_static_with_symtab())
    facts = describe_native(path)["native"]
    assert "imported_symbols" not in facts
    assert "weak_imports" not in facts


def test_no_dynsym_leaves_the_export_fact_out(tmp_path: Path) -> None:
    # An image with section headers but no .dynsym (a static binary keeps only
    # .symtab) exports nothing through the dynamic table; the facts are omitted
    # rather than reported as empty lists.
    path = _write(tmp_path, "a.bin", _elf64_static_with_symtab())
    facts = describe_native(path)["native"]
    assert "exported_symbols" not in facts
    assert "imported_symbols" not in facts


def test_a_symbol_at_a_special_section_index_is_not_exported(tmp_path: Path) -> None:
    # SHN_ABS (and other reserved indices) are not a real section, so an
    # absolute GLOBAL symbol is not part of the export surface -- the reader
    # requires a genuine section index, the way readelf shows "ABS" not a Ndx.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("real_export", _STB_GLOBAL, _STT_FUNC, 10),
                ("abs_symbol", _STB_GLOBAL, _STT_OBJECT, _SHN_ABS),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["exported_symbols"] == ["real_export"]
    # Nor is it an import: a reserved index is defined-elsewhere-by-fiat, not
    # something the loader resolves, so it lands in neither list.
    assert "imported_symbols" not in facts


def test_a_nameless_export_is_skipped(tmp_path: Path) -> None:
    # A defined GLOBAL whose st_name points at the empty string names nothing;
    # the reader skips it rather than reporting an empty symbol, while still
    # reading its well-formed sibling.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [
                ("", _STB_GLOBAL, _STT_FUNC, 10),
                ("named", _STB_GLOBAL, _STT_FUNC, 10),
            ]
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["exported_symbols"] == ["named"]


def test_a_lying_dynsym_size_stays_bounded(tmp_path: Path) -> None:
    # A hostile sh_size far larger than the file cannot force a huge read: the
    # scan is capped and stops at the first short record, keeping the symbols
    # that actually parsed.
    path = _write(
        tmp_path,
        "a.bin",
        _elf64_with_dynsym(
            [("exported_add", _STB_GLOBAL, _STT_FUNC, 10)],
            dynsym_size=24 * 10_000_000,
        ),
    )
    facts = describe_native(path)["native"]
    assert facts["exported_symbols"] == ["exported_add"]


def test_soname_and_build_id_from_a_shared_object(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_shared_with_soname_and_build_id())
    facts = describe_native(path)["native"]
    # DT_SONAME is the provider-side pair to DT_NEEDED, present only on a library.
    assert facts["soname"] == "libmylib.so.1"
    assert facts["needed"] == ["libc.so.6"]
    # The GNU build-id from the PT_NOTE record, hex-encoded.
    assert facts["build_id"] == "deadbeef01020304"


def test_abi_tag_reports_target_os_and_min_kernel(tmp_path: Path) -> None:
    # NT_GNU_ABI_TAG is the ELF LC_BUILD_VERSION: which Unix, how old a kernel.
    # readelf -n decodes this same note as "OS: Linux, ABI: 3.2.0".
    path = _write(tmp_path, "a.bin", _elf64_with_notes(_abi_note(0, 3, 2, 0)))
    facts = describe_native(path)["native"]
    assert facts["abi_os"] == "linux"
    assert facts["min_kernel"] == "3.2.0"


def test_abi_tag_and_build_id_parse_from_the_same_segment(tmp_path: Path) -> None:
    # Both facts come from PT_NOTE records; a real image carries the two in one
    # segment, so the shared walk must surface both, whichever comes first.
    build = _elf_note(3, b"GNU", bytes([0xAB, 0xCD, 0xEF, 0x01]))  # NT_GNU_BUILD_ID
    path = _write(tmp_path, "a.bin", _elf64_with_notes(build + _abi_note(3, 12, 1, 0)))
    facts = describe_native(path)["native"]
    assert facts["build_id"] == "abcdef01"
    assert facts["abi_os"] == "freebsd"
    assert facts["min_kernel"] == "12.1.0"


def test_abi_tag_unknown_os_is_reported_by_number(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_with_notes(_abi_note(99, 1, 0, 0)))
    facts = describe_native(path)["native"]
    assert facts["abi_os"] == "os_99"
    assert facts["min_kernel"] == "1.0.0"


def test_abi_tag_absent_leaves_the_facts_out(tmp_path: Path) -> None:
    # A build-id-only PT_NOTE carries no ABI tag, so those facts stay absent.
    build = _elf_note(3, b"GNU", bytes([0x01, 0x02, 0x03, 0x04]))
    facts = describe_native(_write(tmp_path, "a.bin", _elf64_with_notes(build)))["native"]
    assert "abi_os" not in facts
    assert "min_kernel" not in facts


def test_abi_tag_with_a_truncated_descriptor_is_ignored(tmp_path: Path) -> None:
    # A descriptor shorter than the four u32s it promises cannot be trusted;
    # the note is skipped rather than read past its end.
    short = _elf_note(1, b"GNU", bytes(8))  # only two of the four words
    facts = describe_native(_write(tmp_path, "a.bin", _elf64_with_notes(short)))["native"]
    assert "abi_os" not in facts


def test_static_unstripped_facts_from_section_headers(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_static_with_symtab())
    facts = describe_native(path)["native"]
    assert facts["type"] == "exec"
    assert facts["linking"] == "static"  # PT_LOAD only, no PT_DYNAMIC
    assert facts["pie"] is False
    assert "interpreter" not in facts
    assert facts["stripped"] is False  # a SHT_SYMTAB section is present
    # A static image depends on nothing and declares no soname.
    assert "needed" not in facts
    assert "soname" not in facts
    assert "build_id" not in facts
    # Canary comes from the dynamic string table; a static image has none, so
    # the fact is omitted rather than guessed False.
    assert "canary" not in facts


def test_nx_reflects_the_gnu_stack_permissions(tmp_path: Path) -> None:
    # NX is exactly PT_GNU_STACK-minus-execute: a non-executable stack reads on,
    # an executable one reads off, matching how radare2 decides nx.
    guarded = describe_native(
        _write(tmp_path, "guarded.bin", _elf64_with_gnu_stack(executable=False))
    )["native"]
    assert guarded["nx"] is True
    exec_stack = describe_native(
        _write(tmp_path, "exec.bin", _elf64_with_gnu_stack(executable=True))
    )["native"]
    assert exec_stack["nx"] is False
    # Neither carries PT_GNU_RELRO, so RELRO stays none regardless of the stack.
    assert guarded["relro"] == "none"
    assert exec_stack["relro"] == "none"


def test_wx_segments_counts_only_the_rwe_loads(tmp_path: Path) -> None:
    # A clean split maps text R+X and data R+W; a mapping carrying W and X at
    # once is the packer/self-modifying-code tell, counted exactly.
    program = (
        _phdr64(1, 0x1000, 0x100, 0x1000, p_flags=0x5)  # R+X text
        + _phdr64(1, 0x2000, 0x100, 0x2000, p_flags=0x6)  # R+W data
        + _phdr64(1, 0x3000, 0x100, 0x3000, p_flags=0x7)  # R+W+E: the violation
    )
    ehdr = _ehdr64(2, phoff=64, phnum=3, shoff=0, shnum=0)
    facts = describe_native(_write(tmp_path, "wx.elf", ehdr + program))["native"]
    assert facts["wx_segments"] == 1


def test_a_clean_load_split_counts_zero_wx_segments(tmp_path: Path) -> None:
    program = _phdr64(1, 0x1000, 0x100, 0x1000, p_flags=0x5) + _phdr64(
        1, 0x2000, 0x100, 0x2000, p_flags=0x6
    )
    ehdr = _ehdr64(2, phoff=64, phnum=2, shoff=0, shnum=0)
    facts = describe_native(_write(tmp_path, "clean.elf", ehdr + program))["native"]
    assert facts["wx_segments"] == 0


def test_a_file_less_wx_mapping_still_counts(tmp_path: Path) -> None:
    # p_filesz 0: the bytes arrive at runtime (a decompression target), but
    # the mapping is W+X from the first instruction -- it must count.
    program = _phdr64(1, 0, 0, 0x4000, p_flags=0x7)
    ehdr = _ehdr64(2, phoff=64, phnum=1, shoff=0, shnum=0)
    facts = describe_native(_write(tmp_path, "bss.elf", ehdr + program))["native"]
    assert facts["wx_segments"] == 1


def test_a_header_only_elf_omits_the_wx_census(tmp_path: Path) -> None:
    # No program headers to walk: the census is omitted (like nx/relro), not
    # reported as a misleading zero.
    facts = describe_native(_write(tmp_path, "hdr.elf", _elf64_le()))["native"]
    assert "wx_segments" not in facts


def test_relro_is_partial_without_eager_binding(tmp_path: Path) -> None:
    # PT_GNU_RELRO alone is partial RELRO: the segment exists but the loader is
    # not told to resolve every relocation up front.
    facts = describe_native(_write(tmp_path, "a.bin", _elf64_relro()))["native"]
    assert facts["relro"] == "partial"
    # The non-exec PT_GNU_STACK the builder adds still reads as NX on.
    assert facts["nx"] is True


def test_relro_is_full_when_binding_is_forced_eager(tmp_path: Path) -> None:
    # Any of the three eager-binding markers upgrades partial RELRO to full, so
    # each must independently produce "full".
    for name, kwargs in (
        ("bind_now_tag", {"bind_now_tag": True}),  # DT_BIND_NOW
        ("df_bind_now", {"flags": 0x08}),  # DT_FLAGS & DF_BIND_NOW
        ("df_1_now", {"flags_1": 0x01}),  # DT_FLAGS_1 & DF_1_NOW
    ):
        facts = describe_native(_write(tmp_path, f"{name}.bin", _elf64_relro(**kwargs)))["native"]
        assert facts["relro"] == "full", name


def test_elf_textrel_reads_both_markers_and_defaults_false(tmp_path: Path) -> None:
    # Text relocations -- the dynamic W^X violation checksec's TEXTREL row
    # flags -- are declared by either the legacy DT_TEXTREL tag or DF_TEXTREL
    # in DT_FLAGS; a stock dynamic section carries neither and reads False.
    for name, kwargs in (
        ("textrel_tag", {"textrel_tag": True}),  # DT_TEXTREL
        ("df_textrel", {"flags": 0x04}),  # DT_FLAGS & DF_TEXTREL
    ):
        facts = describe_native(_write(tmp_path, f"{name}.bin", _elf64_relro(**kwargs)))["native"]
        assert facts["textrel"] is True, name
    clean = describe_native(_write(tmp_path, "clean.bin", _elf64_relro()))["native"]
    assert clean["textrel"] is False
    # Eager binding (DF_BIND_NOW is bit 0x08) must not read as text
    # relocations (bit 0x04) -- the flag bits are checked, not mere presence.
    eager = describe_native(_write(tmp_path, "eager.bin", _elf64_relro(flags=0x08)))["native"]
    assert eager["textrel"] is False


def test_elf_without_a_dynamic_section_carries_no_textrel(tmp_path: Path) -> None:
    # A static ELF has no dynamic section for the loader to consult, so the
    # question does not arise and the key is absent rather than False.
    ehdr = _ehdr64(2, phoff=64, phnum=1, shoff=0, shnum=0)  # ET_EXEC
    facts = describe_native(_write(tmp_path, "static.bin", ehdr + _phdr64(1)))["native"]
    assert "textrel" not in facts


def test_elf_entry_point_reported_only_when_nonzero(tmp_path: Path) -> None:
    # e_entry is where execution starts -- the first address an analyst
    # navigates to -- and zero means "no entry point" per the ELF spec, so a
    # zero value is omitted rather than reported as a real address.
    ehdr = _ehdr64(2, phoff=64, phnum=1, shoff=0, shnum=0, entry=0x401_000)  # ET_EXEC
    facts = describe_native(_write(tmp_path, "a.bin", ehdr + _phdr64(1)))["native"]
    assert facts["entry"] == 0x401_000
    zero = _write(tmp_path, "b.bin", _elf64_dynamic_pie())  # helper leaves e_entry 0
    assert "entry" not in describe_native(zero)["native"]


def test_real_elf_pie_versus_shared_object() -> None:
    """A PIE executable and a shared object are both ET_DYN with an interpreter.

    Only the DF_1_PIE dynamic flag tells them apart, so this pins the reader to
    real system binaries: /bin/ls (a PIE executable) must read pie=True while
    libc.so.6 (a shared object) must read pie=False.
    """
    ls = Path("/bin/ls")
    # Target libc.so.6 (the real ELF), never libc.so (often a text ld script).
    libc_candidates = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        *glob.glob("/lib/*/libc.so.6"),
        *glob.glob("/usr/lib/*/libc.so.6"),
    ]
    libc = next((Path(p) for p in libc_candidates if Path(p).is_file()), None)
    if not ls.is_file() or libc is None:
        pytest.skip("need /bin/ls and libc to contrast pie vs shared (skip != pass)")
    ls_facts = describe_native(ls.resolve())["native"]
    libc_facts = describe_native(libc.resolve())["native"]
    assert ls_facts["pie"] is True
    assert ls_facts["linking"] == "dynamic"
    assert ls_facts["interpreter"].startswith("/lib")
    # A modern distro's /bin/ls is hardened: NX on with at least partial RELRO.
    # The native r2 gate pins these to r2's own iI; here they must at least hold
    # the shape a real toolchain produces.
    assert ls_facts["nx"] is True
    assert ls_facts["relro"] in {"partial", "full"}
    # Both are built with the stack protector, so the guard symbol is present.
    assert ls_facts["canary"] is True
    assert libc_facts["canary"] is True
    # A real executable always names where execution starts.
    assert ls_facts["entry"] > 0
    # A real dynamic executable names libc among its DT_NEEDED libraries.
    assert any("libc.so" in name for name in ls_facts["needed"])
    assert libc_facts["pie"] is False
    assert libc_facts["linking"] == "dynamic"
    # libc declares its own soname; a PIE executable like ls does not.
    assert libc_facts.get("soname") == "libc.so.6"
    assert "soname" not in ls_facts
    # A GNU build-id, when the toolchain emitted one, reads back as clean hex.
    for facts in (ls_facts, libc_facts):
        build_id = facts.get("build_id")
        if build_id is not None:
            assert isinstance(build_id, str)
            assert len(build_id) >= 8
            int(build_id, 16)  # raises if not hex


def test_macho_thin_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.dylib", _macho64_le())
    assert classify_target(str(path)) is TargetKind.NATIVE
    assert describe_native(path)["native"] == {
        "format": "macho",
        "bits": 64,
        "endianness": "little",
        "arch": "x86-64",
        "type": "execute",
        "urls": [],
        "url_count": 0,
        "cleartext_url_count": 0,
    }


def test_macho_pie_executable_lists_its_dylibs(tmp_path: Path) -> None:
    dylib = "/usr/lib/libSystem.B.dylib"
    data = _macho64_full(
        filetype=2,  # MH_EXECUTE
        flags=0x00200000 | 0x4,  # MH_PIE | MH_DYLDLINK
        load_cmds=_lc_load_dylib(dylib),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["type"] == "execute"
    assert facts["pie"] is True
    assert facts["linking"] == "dynamic"
    assert facts["dylibs"] == [dylib]


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        out.append(low | 0x80 if value else low)
        if not value:
            return bytes(out)


def _export_trie(names: list[str]) -> bytes:
    """A flat dyld exports trie: one root, one full-name edge per export.

    Each child is a terminal node (terminal size 2: flags 0, address 0, then
    zero children). Offsets are resolved to a fixed point so the ULEB widths
    stay consistent with the layout they describe.
    """
    terminal = bytes([2, 0, 0, 0])
    offsets = [0] * len(names)
    while True:
        blob = bytearray([0, len(names)])  # root: not terminal, N children
        for name, off in zip(names, offsets, strict=True):
            blob += name.encode() + b"\x00" + _uleb(off)
        resolved = []
        pos = len(blob)
        for _ in names:
            resolved.append(pos)
            pos += len(terminal)
        if resolved == offsets:
            return bytes(blob) + terminal * len(names)
        offsets = resolved


def _lc_dyld_info(export_off: int, export_size: int) -> bytes:
    # dyld_info_command: five (off, size) pairs; only the export pair matters.
    cmd = bytearray(48)
    cmd[0:4] = (0x80000022).to_bytes(4, "little")  # LC_DYLD_INFO_ONLY
    cmd[4:8] = (48).to_bytes(4, "little")
    cmd[40:44] = export_off.to_bytes(4, "little")
    cmd[44:48] = export_size.to_bytes(4, "little")
    return bytes(cmd)


def _lc_exports_trie(dataoff: int, datasize: int) -> bytes:
    # linkedit_data_command: the chained-fixups era home of the same trie.
    cmd = bytearray(16)
    cmd[0:4] = (0x80000033).to_bytes(4, "little")
    cmd[4:8] = (16).to_bytes(4, "little")
    cmd[8:12] = dataoff.to_bytes(4, "little")
    cmd[12:16] = datasize.to_bytes(4, "little")
    return bytes(cmd)


def _macho_with_trie(trie: bytes, *, via_dyld_info: bool = True) -> bytes:
    load = (
        _lc_dyld_info(32 + 48, len(trie)) if via_dyld_info else _lc_exports_trie(32 + 16, len(trie))
    )
    return _macho64_full(filetype=2, flags=0, load_cmds=load, ncmds=1) + trie


class TestMachoDyldExports:
    """describe_native reads the dyld exports trie -- the loader's export list.

    The trie is what dyld actually binds against and it survives strip, where
    LC_SYMTAB's externals may not: for a stripped modern dylib it is the only
    export surface left in the file. llvm-objdump --exports-trie decodes the
    same structure in the gate. Present only when the image carries a trie
    with entries; reported beside the symtab facts, not merged into them.
    """

    def test_a_dyld_info_trie_names_the_exports(self, tmp_path: Path) -> None:
        data = _macho_with_trie(_export_trie(["_launch", "_teardown"]))
        facts = describe_native(_write(tmp_path, "info.dylib", data))["native"]
        assert facts["dyld_exports"] == ["_launch", "_teardown"]
        # No LC_SYMTAB at all -- the stripped-dylib shape this fact exists
        # for: the symtab surface is silent, the trie still answers.
        assert "exported_symbols" not in facts

    def test_an_lc_exports_trie_command_reads_the_same(self, tmp_path: Path) -> None:
        data = _macho_with_trie(_export_trie(["_main"]), via_dyld_info=False)
        facts = describe_native(_write(tmp_path, "fixups.dylib", data))["native"]
        assert facts["dyld_exports"] == ["_main"]

    def test_shared_prefixes_accumulate_across_edges(self, tmp_path: Path) -> None:
        # Hand-built two-level trie: root --"_get"--> mid --"A"/"B"--> leaves.
        # A reader emitting edge substrings instead of accumulated paths would
        # report "A"/"B"; one stopping at the first terminal would miss both.
        trie = bytes(
            [0, 1, *b"_get", 0, 8]  # root at 0: one edge "_get" -> node 8
            + [0, 2, ord("A"), 0, 16, ord("B"), 0, 20]  # mid: "A"->16, "B"->20
            + [2, 0, 0, 0]  # terminal A
            + [2, 0, 0, 0]  # terminal B
        )
        data = _macho_with_trie(trie)
        facts = describe_native(_write(tmp_path, "prefix.dylib", data))["native"]
        assert facts["dyld_exports"] == ["_getA", "_getB"]

    def test_a_cyclic_child_offset_cannot_loop_the_walk(self, tmp_path: Path) -> None:
        # A hostile child pointing back at the root: each node is visited
        # once, no terminal is ever reached, and the fact stays absent.
        trie = bytes([0, 1, ord("x"), 0, 0])
        data = _macho_with_trie(trie)
        facts = describe_native(_write(tmp_path, "cycle.dylib", data))["native"]
        assert "dyld_exports" not in facts

    def test_a_zero_sized_export_pair_reads_no_trie(self, tmp_path: Path) -> None:
        data = _macho64_full(filetype=2, flags=0, load_cmds=_lc_dyld_info(0x2000, 0), ncmds=1)
        facts = describe_native(_write(tmp_path, "notrie.dylib", data))["native"]
        assert "dyld_exports" not in facts

    def test_the_committed_fixture_has_no_trie(self, tmp_path: Path) -> None:
        # The fixture predates chained fixups and carries no LC_DYLD_INFO;
        # absence here keeps the fact honest on real non-trie images.
        if not _MACHO_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")
        facts = describe_native(_MACHO_FIXTURE)["native"]
        assert "dyld_exports" not in facts


class TestMachoDylibClasses:
    """describe_native names the weak and reexported dylibs apart.

    All three command kinds land in ``dylibs`` (the full dependency set), but
    a weak dylib is optional capability the image probes for at runtime --
    dyld leaves its symbols null when the library is missing, the Mach-O pair
    to PE delay imports -- and a reexported dylib is API forwarding (a facade
    whose exports live elsewhere). Both subset facts ride whenever the dylib
    walk ran: empty is a real answer.
    """

    def test_weak_and_reexported_dylibs_split_out_of_the_plain_list(
        self, tmp_path: Path
    ) -> None:
        plain = "/usr/lib/libSystem.B.dylib"
        weak = "/usr/lib/swift/libswiftCore.dylib"
        fronted = "/usr/lib/libcore_real.dylib"
        cmds = (
            _lc_load_dylib(plain)
            + _lc_load_dylib(weak, cmd_kind=0x80000018)  # LC_LOAD_WEAK_DYLIB
            + _lc_load_dylib(fronted, cmd_kind=0x8000001F)  # LC_REEXPORT_DYLIB
        )
        data = _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=3)
        facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
        # The full set keeps command order; the subsets name their own kinds.
        assert facts["dylibs"] == [plain, weak, fronted]
        assert facts["weak_dylibs"] == [weak]
        assert facts["reexported_dylibs"] == [fronted]

    def test_plain_dependencies_read_empty_subsets(self, tmp_path: Path) -> None:
        data = _macho64_full(
            filetype=2, flags=0x4, load_cmds=_lc_load_dylib("/usr/lib/libc.dylib"), ncmds=1
        )
        facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
        assert facts["weak_dylibs"] == []
        assert facts["reexported_dylibs"] == []

    def test_no_load_commands_at_all_omits_the_subsets_too(self, tmp_path: Path) -> None:
        # Without a dylib walk there is no dependency answer of any class --
        # the subsets stay absent exactly when ``dylibs`` does.
        data = _macho64_full(filetype=2, flags=0, load_cmds=b"", ncmds=0)
        facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
        assert "dylibs" not in facts
        assert "weak_dylibs" not in facts
        assert "reexported_dylibs" not in facts


def test_macho_dylib_is_dynamic_but_not_pie(tmp_path: Path) -> None:
    # A .dylib is position-independent by nature but does not set MH_PIE, so it
    # reads pie=False -- the same contract as an ELF shared object.
    data = _macho64_full(filetype=6, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)  # MH_DYLIB
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["type"] == "dylib"
    assert facts["pie"] is False
    assert facts["linking"] == "dynamic"
    assert facts["dylibs"] == []  # a load command is present, but none are dylibs
    assert facts["uuid"] == "00000000-0000-0000-0000-000000000000"  # LC_UUID was read


def test_macho_static_executable_has_no_dylibs(tmp_path: Path) -> None:
    data = _macho64_full(filetype=2, flags=0, load_cmds=b"", ncmds=0)
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["pie"] is False
    assert facts["linking"] == "static"
    assert "dylibs" not in facts
    assert "interpreter" not in facts


def test_macho_records_its_dynamic_linker(tmp_path: Path) -> None:
    # LC_LOAD_DYLINKER is the Mach-O PT_INTERP: it names the loader, so a native
    # session reports it the way it reports an ELF's interpreter.
    dyld = "/usr/lib/dyld"
    lib = "/usr/lib/libSystem.B.dylib"
    data = _macho64_full(
        filetype=2,  # MH_EXECUTE
        flags=0x00200000 | 0x4,  # MH_PIE | MH_DYLDLINK
        load_cmds=_lc_load_dylinker(dyld) + _lc_load_dylib(lib),
        ncmds=2,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["interpreter"] == dyld
    assert facts["dylibs"] == [lib]


def test_macho_rpaths_collected_in_command_order(tmp_path: Path) -> None:
    # LC_RPATH is the Mach-O rpath/runpath: each command carries one search
    # path, kept verbatim (dyld expands @loader_path, not the reader) and in
    # the order dyld would walk them.
    data = _macho64_full(
        filetype=2,  # MH_EXECUTE
        flags=0x4,  # MH_DYLDLINK
        load_cmds=_lc_rpath("@loader_path/../Frameworks") + _lc_rpath("/opt/lib"),
        ncmds=2,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["rpath"] == ["@loader_path/../Frameworks", "/opt/lib"]


def test_macho_without_lc_rpath_has_no_rpath_fact(tmp_path: Path) -> None:
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)
    assert "rpath" not in describe_native(_write(tmp_path, "a.bin", data))["native"]


def test_macho_rpath_with_a_hostile_string_offset_is_dropped(tmp_path: Path) -> None:
    # An lc_str offset pointing past its own command cannot be resolved; that
    # command is skipped rather than read out of bounds or guessed.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_rpath("/opt/lib", name_offset=4096) + _lc_rpath("/usr/lib"),
        ncmds=2,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["rpath"] == ["/usr/lib"]


def test_macho_build_version_names_platform_and_versions(tmp_path: Path) -> None:
    # LC_BUILD_VERSION answers the first Apple-binary question: which platform,
    # how old. Versions are nibble-packed xxxx.yy.zz; the patch level prints
    # only when nonzero, matching llvm-objdump's spelling.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_build_version(2, 0x000F0401, 0x00110000),  # iOS 15.4.1, SDK 17.0
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["platform"] == "ios"
    assert facts["min_os"] == "15.4.1"
    assert facts["sdk"] == "17.0"


def test_macho_build_version_reports_the_toolchain(tmp_path: Path) -> None:
    # The trailing build_tool_version entries are the toolchain provenance --
    # the Mach-O pair to an ELF .comment and the WASM producers section.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_build_version(
            1,
            0x000E0000,
            0x000E0500,
            tools=((3, (1095 << 16) | (2 << 8)), (1, 15 << 16)),  # ld 1095.2, clang 15.0
        ),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["build_tools"] == [
        {"tool": "ld", "version": "1095.2"},
        {"tool": "clang", "version": "15.0"},
    ]


def test_macho_build_version_without_tools_reports_no_toolchain(tmp_path: Path) -> None:
    data = _macho64_full(
        filetype=2, flags=0x4, load_cmds=_lc_build_version(1, 0x000E0000, 0), ncmds=1
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["platform"] == "macos"
    assert "build_tools" not in facts


def test_macho_a_lying_ntools_stays_inside_its_command(tmp_path: Path) -> None:
    # ntools claims five entries but the command holds one: the walk must stop
    # at the command's own boundary, not read the next command as tools.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_build_version(
            1, 0x000E0000, 0, tools=((3, 900 << 16),), declared_ntools=5
        ),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["build_tools"] == [{"tool": "ld", "version": "900.0"}]


def test_macho_an_unknown_tool_id_reads_numerically(tmp_path: Path) -> None:
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_build_version(1, 0x000E0000, 0, tools=((9, 7 << 16),)),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["build_tools"] == [{"tool": "tool_9", "version": "7.0"}]


def test_macho_version_min_command_kind_names_the_platform(tmp_path: Path) -> None:
    # The pre-LC_BUILD_VERSION encoding: LC_VERSION_MIN_MACOSX (0x24) et al.
    # carry version+sdk, with the platform implied by the command itself.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_version_min(0x24, 0x000A0D00, 0x000A0E00),  # macOS 10.13, SDK 10.14
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["platform"] == "macos"
    assert facts["min_os"] == "10.13"
    assert facts["sdk"] == "10.14"


def test_macho_without_version_commands_has_no_platform_facts(tmp_path: Path) -> None:
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert "platform" not in facts
    assert "min_os" not in facts
    assert "sdk" not in facts


def test_macho_zero_sdk_and_unknown_platform_degrade_gracefully(tmp_path: Path) -> None:
    # An sdk of 0 is llvm-objdump's "n/a": no fact rather than "0.0". An
    # unrecognised platform id is reported by number, not guessed.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_build_version(99, 0x000D0000, 0),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["platform"] == "platform_99"
    assert facts["min_os"] == "13.0"
    assert "sdk" not in facts


def test_macho_records_uuid_and_install_name(tmp_path: Path) -> None:
    # LC_ID_DYLIB is the Mach-O DT_SONAME and LC_UUID the Mach-O build-id, so a
    # dylib reports both the way an ELF shared object reports soname/build_id.
    install = "/usr/lib/libmylib.dylib"
    data = _macho64_full(
        filetype=6,  # MH_DYLIB
        flags=0x4,  # MH_DYLDLINK
        load_cmds=_lc_id_dylib(install) + _lc_uuid_bytes(bytes(range(16))),
        ncmds=2,
    )
    facts = describe_native(_write(tmp_path, "a.dylib", data))["native"]
    assert facts["install_name"] == install
    assert facts["uuid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f"


def test_macho_entry_point_mapped_through_its_segment(tmp_path: Path) -> None:
    # LC_MAIN records where execution starts as a file offset, unlike ELF's
    # e_entry which is already an address, so the covering segment supplies the
    # translation: vmaddr + (entryoff - fileoff).
    data = _macho64_full(
        filetype=2,  # MH_EXECUTE
        flags=0x00200000 | 0x4,  # MH_PIE | MH_DYLDLINK
        load_cmds=_lc_segment64(0x100000000, 0, 0x2000) + _lc_main(0x1D0),
        ncmds=2,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["entry"] == 0x1000001D0


def test_macho_entry_outside_every_segment_is_not_fabricated(tmp_path: Path) -> None:
    # A hostile or truncated image whose LC_MAIN offset no segment covers gets
    # no entry fact rather than an invented address.
    data = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_segment64(0x100000000, 0, 0x100) + _lc_main(0x5000),
        ncmds=2,
    )
    assert "entry" not in describe_native(_write(tmp_path, "a.bin", data))["native"]


def test_macho32_entry_uses_the_32bit_segment_layout(tmp_path: Path) -> None:
    # The 32-bit segment_command packs vmaddr/fileoff/filesize as u32s at
    # different offsets than segment_command_64; the mapping must follow suit.
    data = _macho32_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_segment32(0x1000, 0, 0x2000) + _lc_main(0x400),
        ncmds=2,
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["bits"] == 32
    assert facts["entry"] == 0x1400


def test_macho_nx_reflects_the_stack_execution_flag(tmp_path: Path) -> None:
    # The stack is non-executable unless the image opts in with
    # MH_ALLOW_STACK_EXECUTION -- the inverse of ELF's PT_GNU_STACK PF_X bit.
    hardened = _macho64_full(filetype=2, flags=0x4, load_cmds=b"", ncmds=0)
    assert describe_native(_write(tmp_path, "a.bin", hardened))["native"]["nx"] is True
    execstack = _macho64_full(filetype=2, flags=0x4 | 0x00020000, load_cmds=b"", ncmds=0)
    assert describe_native(_write(tmp_path, "b.bin", execstack))["native"]["nx"] is False


def test_macho_wx_segments_counts_rwx_initprot(tmp_path: Path) -> None:
    # initprot carrying write and execute at once is the Mach-O W^X
    # violation, the pair to a RWE PT_LOAD; a clean R+X text does not count.
    cmds = _lc_segment64(0x1000, 0, 0x1000, initprot=0x5) + _lc_segment64(
        0x2000, 0x1000, 0x100, initprot=0x7
    )
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=2)
    facts = describe_native(_write(tmp_path, "wx.macho", data))["native"]
    assert facts["wx_segments"] == 1


def test_macho_a_clean_image_counts_zero_wx_segments(tmp_path: Path) -> None:
    cmds = _lc_segment64(0x1000, 0, 0x1000, initprot=0x5)
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1)
    facts = describe_native(_write(tmp_path, "clean.macho", data))["native"]
    assert facts["wx_segments"] == 0


def test_macho32_wx_reads_initprot_at_its_32bit_offset(tmp_path: Path) -> None:
    # The 32-bit segment_command packs initprot at +44, not +60.
    cmds = _lc_segment32(0x1000, 0, 0x1000, initprot=0x7)
    data = _macho32_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1)
    facts = describe_native(_write(tmp_path, "wx32.macho", data))["native"]
    assert facts["wx_segments"] == 1


def test_macho_encrypted_from_the_encryption_info_cryptid(tmp_path: Path) -> None:
    """LC_ENCRYPTION_INFO's cryptid is the FairPlay question for an iOS binary.

    cryptid != 0 means __TEXT is ciphertext on disk and static analysis reads
    garbage until the image is dumped decrypted -- the first triage fact for an
    App Store binary. A decrypted (cryptid 0) or never-encrypted image reads
    False.
    """
    encrypted = _macho64_full(
        filetype=2, flags=0x4, load_cmds=_lc_encryption_info(1), ncmds=1
    )
    assert describe_native(_write(tmp_path, "a.bin", encrypted))["native"]["encrypted"] is True
    # The 32-bit command (0x21) decodes identically.
    encrypted32 = _macho64_full(
        filetype=2, flags=0x4, load_cmds=_lc_encryption_info(1, cmd=0x21), ncmds=1
    )
    assert describe_native(_write(tmp_path, "b.bin", encrypted32))["native"]["encrypted"] is True
    decrypted = _macho64_full(
        filetype=2, flags=0x4, load_cmds=_lc_encryption_info(0), ncmds=1
    )
    assert describe_native(_write(tmp_path, "c.bin", decrypted))["native"]["encrypted"] is False
    plain = _macho64_full(filetype=2, flags=0x4, load_cmds=b"", ncmds=0)
    assert describe_native(_write(tmp_path, "d.bin", plain))["native"]["encrypted"] is False


def test_macho_encryption_info_reports_the_opaque_range(tmp_path: Path) -> None:
    """The full encryption_info triple maps which file bytes are ciphertext.

    encrypted answers *whether*; the range answers *what* -- cryptoff/cryptsize
    bound the region static analysis cannot read until the image is dumped,
    and cryptid names the scheme (1 = FairPlay). The command's mere presence
    with cryptid 0 is itself a fact: that is the shape of a decrypted App
    Store dump, distinct from a never-encrypted build which carries no
    command at all.
    """
    encrypted = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_encryption_info(1, cryptoff=0x4000, cryptsize=0x14000),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "enc.bin", encrypted))["native"]
    assert facts["encrypted"] is True
    assert facts["encryption_info"] == {"offset": 0x4000, "size": 0x14000, "cryptid": 1}

    # A decrypted dump: the command survives with cryptid 0 -- the range is
    # still reported (it is now plaintext), and the telltale is auditable.
    dumped = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_encryption_info(0, cryptoff=0x4000, cryptsize=0x14000),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "dump.bin", dumped))["native"]
    assert facts["encrypted"] is False
    assert facts["encryption_info"] == {"offset": 0x4000, "size": 0x14000, "cryptid": 0}

    # The 32-bit command (0x21) carries the same triple at the same offsets.
    encrypted32 = _macho64_full(
        filetype=2,
        flags=0x4,
        load_cmds=_lc_encryption_info(1, cmd=0x21, cryptoff=0x2000, cryptsize=0x3000),
        ncmds=1,
    )
    facts = describe_native(_write(tmp_path, "enc32.bin", encrypted32))["native"]
    assert facts["encryption_info"] == {"offset": 0x2000, "size": 0x3000, "cryptid": 1}

    # A never-encrypted image carries no command, hence no range at all --
    # absence is the fact, not a zeroed placeholder.
    plain = _macho64_full(filetype=2, flags=0x4, load_cmds=b"", ncmds=0)
    assert "encryption_info" not in describe_native(_write(tmp_path, "p.bin", plain))["native"]


def test_macho_canary_from_the_symbol_string_table(tmp_path: Path) -> None:
    # A -fstack-protector build imports ___stack_chk_guard/_fail from
    # libSystem; their names sit in LC_SYMTAB's string table, the same place
    # the ELF reader greps dynstr. One leading underscore more than the ELF
    # spelling, which the substring scan absorbs.
    guarded_tab = b"\x00_main\x00___stack_chk_guard\x00___stack_chk_fail\x00"
    cmds = _lc_symtab(stroff=32 + 24, strsize=len(guarded_tab))
    guarded = _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1) + guarded_tab
    assert describe_native(_write(tmp_path, "a.bin", guarded))["native"]["canary"] is True

    bare_tab = b"\x00_main\x00_printf\x00"
    cmds = _lc_symtab(stroff=32 + 24, strsize=len(bare_tab))
    bare = _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1) + bare_tab
    assert describe_native(_write(tmp_path, "b.bin", bare))["native"]["canary"] is False


def test_macho_without_a_symtab_has_no_canary_fact(tmp_path: Path) -> None:
    # No symbol table means the question cannot be answered: no fact, rather
    # than a fabricated False -- the ELF reader's posture for a static binary.
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)
    assert "canary" not in describe_native(_write(tmp_path, "a.bin", data))["native"]


def test_macho_exported_symbols_lists_defined_externals(tmp_path: Path) -> None:
    # The Mach-O export surface: external symbols defined in a section here.
    # An undefined external is an import (LC_LOAD_DYLIB's job) and a defined
    # local is internal; neither is exported. llvm-nm selects the same set.
    data = _macho64_with_symbols(
        [
            ("_exported_fn", _N_SECT | _N_EXT, 1),
            ("_exported_var", _N_SECT | _N_EXT, 2),
            ("_imported_puts", _N_UNDF | _N_EXT, 0),
            ("_local_helper", _N_SECT, 1),
        ]
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["exported_symbols"] == ["_exported_fn", "_exported_var"]
    # The same walk sends the undefined external to the import side, and the
    # non-external local to neither.
    assert facts["imported_symbols"] == ["_imported_puts"]


def test_macho_without_a_symtab_has_no_export_fact(tmp_path: Path) -> None:
    # No LC_SYMTAB means nothing to enumerate; the facts are omitted rather
    # than reported as empty lists.
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert "exported_symbols" not in facts
    assert "imported_symbols" not in facts


class TestMachoStripped:
    """describe_native reports whether a Mach-O's local symbols are gone.

    ``strip`` removes the local symbols -- the debug-map STABS a ``-g`` build
    carries and the local defined symbols -- while leaving the external symbols
    dyld needs for linking. So a stripped image is one whose symbol table has
    become all-external, the Mach-O pair to the ELF ``stripped`` fact.
    """

    def test_an_all_external_table_reads_stripped(self, tmp_path: Path) -> None:
        # Only externals survive stripping: a defined export and an undefined
        # import, nothing local left.
        data = _macho64_with_symbols(
            [("_main", _N_SECT | _N_EXT, 1), ("_puts", _N_UNDF | _N_EXT, 0)]
        )
        facts = describe_native(_write(tmp_path, "s.bin", data))["native"]
        assert facts["stripped"] is True

    def test_a_local_defined_symbol_reads_unstripped(self, tmp_path: Path) -> None:
        data = _macho64_with_symbols(
            [("_main", _N_SECT | _N_EXT, 1), ("_helper", _N_SECT, 1)]
        )
        facts = describe_native(_write(tmp_path, "u.bin", data))["native"]
        assert facts["stripped"] is False

    def test_a_stab_debug_entry_reads_unstripped(self, tmp_path: Path) -> None:
        # N_SO (0x64) is a STABS debug-map entry: exactly what a -g build
        # carries and strip removes, so its presence means not stripped.
        data = _macho64_with_symbols([("_main", _N_SECT | _N_EXT, 1), ("src.c", 0x64, 0)])
        facts = describe_native(_write(tmp_path, "g.bin", data))["native"]
        assert facts["stripped"] is False

    def test_a_nameless_local_does_not_count(self, tmp_path: Path) -> None:
        # A local slot with a zero string index carries no name to recover;
        # it is not the named local that makes an image worth reversing.
        data = _macho64_with_symbols([("_main", _N_SECT | _N_EXT, 1), ("", _N_SECT, 1)])
        facts = describe_native(_write(tmp_path, "n.bin", data))["native"]
        assert facts["stripped"] is True

    def test_no_symtab_omits_the_fact(self, tmp_path: Path) -> None:
        data = _macho64_full(filetype=2, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)
        facts = describe_native(_write(tmp_path, "b.bin", data))["native"]
        assert "stripped" not in facts


def test_macho_only_imports_export_nothing(tmp_path: Path) -> None:
    # A symbol table of nothing but undefined externals (pure imports) has no
    # export surface: the import fact carries them all, the export fact stays out.
    data = _macho64_with_symbols(
        [
            ("_dyld_stub_binder", _N_UNDF | _N_EXT, 0),
            ("_printf", _N_UNDF | _N_EXT, 0),
        ]
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert "exported_symbols" not in facts
    assert facts["imported_symbols"] == ["_dyld_stub_binder", "_printf"]


def test_macho_fortify_source_names_the_chk_wrappers(tmp_path: Path) -> None:
    # A _FORTIFY_SOURCE build imports libSystem's fortified wrappers, each an
    # undefined external named ___<func>_chk (the C __<func>_chk plus Mach-O's
    # leading underscore). The same rule the ELF reader uses catches them.
    data = _macho64_with_symbols(
        [
            ("___strcpy_chk", _N_UNDF | _N_EXT, 0),
            ("___memcpy_chk", _N_UNDF | _N_EXT, 0),
            ("_printf", _N_UNDF | _N_EXT, 0),
        ]
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["fortify_source"] is True
    assert facts["fortified_functions"] == ["___memcpy_chk", "___strcpy_chk"]


def test_macho_canary_symbols_are_not_fortify_wrappers(tmp_path: Path) -> None:
    # The stack-protector imports end in _fail/_guard, not _chk, so a canaried
    # but unfortified image reads fortify_source False -- the two mitigations
    # stay distinct exactly as on ELF.
    data = _macho64_with_symbols(
        [
            ("___stack_chk_fail", _N_UNDF | _N_EXT, 0),
            ("___stack_chk_guard", _N_UNDF | _N_EXT, 0),
        ]
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["fortify_source"] is False
    assert facts["fortified_functions"] == []


def test_macho_nameless_export_is_skipped(tmp_path: Path) -> None:
    # A defined external whose n_strx is zero names nothing; the reader skips
    # it rather than reporting an empty symbol, while still reading its sibling.
    data = _macho64_with_symbols(
        [
            ("", _N_SECT | _N_EXT, 1),
            ("_named", _N_SECT | _N_EXT, 1),
        ]
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["exported_symbols"] == ["_named"]


def test_macho_lying_nsyms_stays_bounded(tmp_path: Path) -> None:
    # A hostile nsyms far larger than the file cannot force a huge read: the
    # scan stops at the first short record, keeping the symbols that parsed.
    data = _macho64_with_symbols(
        [("_exported_fn", _N_SECT | _N_EXT, 1)], nsyms=10_000_000
    )
    facts = describe_native(_write(tmp_path, "a.bin", data))["native"]
    assert facts["exported_symbols"] == ["_exported_fn"]


def _lc_code_signature(dataoff: int, datasize: int) -> bytes:
    # linkedit_data_command: dataoff/datasize locate the signature SuperBlob.
    return (
        (0x1D).to_bytes(4, "little")
        + (16).to_bytes(4, "little")
        + dataoff.to_bytes(4, "little")
        + datasize.to_bytes(4, "little")
    )


def _code_directory(
    identifier: bytes = b"com.example.app\x00",
    team: bytes | None = None,
    flags: int = 0x2,
    version: int = 0x20400,
    hash_type: int = 2,
) -> bytes:
    """A CodeDirectory blob through the teamOffset field (52-byte header).

    All fields big-endian per the CS spec: magic, length, version, flags,
    hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit, then the
    hashSize/hashType/platform/pageSize bytes, spare2, scatterOffset and
    teamOffset. The identifier (and team, when given) trail the header.
    """
    ident_off = 52
    team_off = ident_off + len(identifier) if team else 0
    body = identifier + (team or b"")
    length = 52 + len(body)
    return (
        struct.pack(">IIIIIIIII", 0xFADE0C02, length, version, flags, 0, ident_off, 0, 0, 0)
        + bytes([32, hash_type, 0, 12])  # hashSize, hashType, platform, pageSize
        + struct.pack(">III", 0, 0, team_off)  # spare2, scatterOffset, teamOffset
        + body
    )


def _superblob(cd: bytes, slot: int = 0) -> bytes:
    # SuperBlob header (magic, length, count) plus one index entry pointing at
    # the CodeDirectory right after it.
    length = 20 + len(cd)
    return struct.pack(">III", 0xFADE0CC0, length, 1) + struct.pack(">II", slot, 20) + cd


def _signed_macho(superblob: bytes) -> bytes:
    # The signature blob rides at a fixed offset past the header + command.
    dataoff = 256
    lc = _lc_code_signature(dataoff, len(superblob))
    image = _macho64_full(filetype=2, flags=0x4, load_cmds=lc, ncmds=1)
    return image.ljust(dataoff, b"\x00") + superblob


def test_macho_signature_reports_identifier_adhoc_and_cdhash(tmp_path: Path) -> None:
    """The macOS "who signed it": identifier, ad-hoc flag and the CD digest.

    cd_sha256 is the SHA-256 over the CodeDirectory blob itself -- what
    Apple's tooling derives the cdhash from and what rcodesign prints, so the
    codesign gate compares the reader's hex against the real signer's.
    """
    cd = _code_directory()
    facts = describe_native(_write(tmp_path, "a.bin", _signed_macho(_superblob(cd))))["native"]
    assert facts["signed"] is True
    assert facts["signature"] == {
        "ad_hoc": True,
        "identifier": "com.example.app",
        "team_id": None,
        "hash_type": "sha256",
        "cd_sha256": hashlib.sha256(cd).hexdigest(),
    }


def test_macho_signature_with_a_team_id(tmp_path: Path) -> None:
    # A certificate-backed signature records the developer's team id; flags
    # without CS_ADHOC read as a real (non-ad-hoc) signature.
    cd = _code_directory(team=b"ABCDE12345\x00", flags=0x0)
    facts = describe_native(_write(tmp_path, "t.bin", _signed_macho(_superblob(cd))))["native"]
    assert facts["signature"]["ad_hoc"] is False
    assert facts["signature"]["team_id"] == "ABCDE12345"


def test_macho_without_lc_code_signature_is_unsigned(tmp_path: Path) -> None:
    data = _macho64_full(filetype=2, flags=0x4, load_cmds=_lc_uuid(), ncmds=1)
    facts = describe_native(_write(tmp_path, "u.bin", data))["native"]
    assert facts["signed"] is False
    assert "signature" not in facts


def test_macho_signature_pointing_at_garbage_reports_signed_only(tmp_path: Path) -> None:
    # The command exists but its blob is not a SuperBlob: the image is still
    # "signed" (the command is there) but no identity is invented from noise.
    facts = describe_native(_write(tmp_path, "g.bin", _signed_macho(b"\xde\xad" * 40)))["native"]
    assert facts["signed"] is True
    assert "signature" not in facts


def test_macho_signature_with_a_lying_cd_length_is_dropped(tmp_path: Path) -> None:
    # The CodeDirectory claims more bytes than the blob holds: nothing is
    # hashed or decoded from out-of-bounds memory.
    cd = _code_directory()
    lying = cd[:4] + (0x7FFFFFFF).to_bytes(4, "big") + cd[8:]
    facts = describe_native(_write(tmp_path, "l.bin", _signed_macho(_superblob(lying))))["native"]
    assert facts["signed"] is True
    assert "signature" not in facts


def test_macho_signature_old_cd_version_reads_no_team_field(tmp_path: Path) -> None:
    # A pre-0x20200 CodeDirectory has no teamOffset field; whatever bytes sit
    # at that position are scatterOffset-era data and must not be decoded as a
    # team string, even when nonzero.
    cd = _code_directory(team=b"NOTATEAM12\x00", version=0x20100)
    facts = describe_native(_write(tmp_path, "o.bin", _signed_macho(_superblob(cd))))["native"]
    assert facts["signature"]["team_id"] is None
    assert facts["signature"]["identifier"] == "com.example.app"


def test_macho_superblob_without_a_codedirectory_slot(tmp_path: Path) -> None:
    # A SuperBlob whose only entry is some other slot (the CMS signature):
    # signed, but no CodeDirectory means no identity facts.
    cd = _code_directory()
    facts = describe_native(
        _write(tmp_path, "s.bin", _signed_macho(_superblob(cd, slot=0x10000)))
    )["native"]
    assert facts["signed"] is True
    assert "signature" not in facts


def test_committed_macho_fixture_entry_matches_its_layout() -> None:
    # The committed fixture's LC_MAIN points at its code blob inside __TEXT
    # (vmaddr 0x100000000, fileoff 0), so the mapped entry is a known constant
    # the r2/Ghidra gates also cross-check against real tool output.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")
    facts = describe_native(fixture)["native"]
    assert facts["entry"] == 0x100000440
    # Its build posture, cross-checked against radare2 by the r2 gate: NX on,
    # stack-protector imports present, no FairPlay encryption.
    assert facts["nx"] is True
    assert facts["canary"] is True
    assert facts["encrypted"] is False
    # The load-time constructor surface: the __DATA segment carries one
    # __mod_init_func and one __mod_term_func pointer, whose section types
    # llvm-objdump independently confirms in the toolchain gate.
    assert facts["init_funcs"] == {"mod_init": 1, "mod_term": 1}
    # The one symbol the fixture defines externally (_main); the stack_chk pair
    # are undefined imports on the other side of the split. The toolchain gate
    # cross-checks both sets against llvm-nm.
    assert facts["exported_symbols"] == ["_main"]
    assert facts["imported_symbols"] == ["___stack_chk_fail", "___stack_chk_guard"]
    # Canaried but not fortified: the stack_chk imports end in _fail/_guard,
    # so the FORTIFY posture reads a definitive False on the real fixture.
    assert facts["fortify_source"] is False
    assert facts["fortified_functions"] == []
    # The committed fixture ships unsigned (the codesign gate signs a copy
    # with rcodesign and cross-checks the signature facts on that).
    assert facts["signed"] is False
    assert "signature" not in facts
    # The @rpath search path baked in by LC_RPATH, which llvm-objdump
    # independently confirms in the toolchain gate.
    assert facts["rpath"] == ["@loader_path/../Frameworks"]
    # LC_BUILD_VERSION's target identity, which llvm-objdump (platform/minos/
    # sdk) and radare2 (its os line) independently confirm in the gates.
    assert facts["platform"] == "macos"
    assert facts["min_os"] == "13.0"
    assert facts["sdk"] == "14.2"


def test_macho_init_and_term_pointer_sections_are_counted(tmp_path: Path) -> None:
    # dyld calls every 8-byte pointer in S_MOD_INIT_FUNC_POINTERS before main
    # and every S_MOD_TERM_FUNC_POINTERS pointer after -- the Mach-O
    # counterpart of the ELF init_array/fini_array counts.
    cmds = _lc_segment64_with_sections([(0x9, 24), (0xA, 8)])
    facts = describe_native(
        _write(tmp_path, "a.bin", _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1))
    )["native"]
    assert facts["init_funcs"] == {"mod_init": 3, "mod_term": 1}


def test_macho_init_offsets_section_counts_u32_entries(tmp_path: Path) -> None:
    # The chained-fixups era encoding: S_INIT_FUNC_OFFSETS holds 32-bit
    # offsets regardless of pointer width, so 12 bytes is three constructors.
    cmds = _lc_segment64_with_sections([(0x16, 12)])
    facts = describe_native(
        _write(tmp_path, "a.bin", _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1))
    )["native"]
    assert facts["init_funcs"] == {"mod_init": 3, "mod_term": 0}


def test_macho_ordinary_sections_add_no_init_entries(tmp_path: Path) -> None:
    # A regular section and a cstring section carry code/data, not
    # constructors; an image with none reads as a zeroed surface -- "runs
    # nothing before main" is a real answer.
    cmds = _lc_segment64_with_sections([(0x0, 64), (0x2, 32)])
    facts = describe_native(
        _write(tmp_path, "a.bin", _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1))
    )["native"]
    assert facts["init_funcs"] == {"mod_init": 0, "mod_term": 0}


def test_macho_32bit_init_sections_use_4_byte_pointers(tmp_path: Path) -> None:
    # A 32-bit image's mod_init pointers are 4 bytes wide, so the same byte
    # size means twice the constructors.
    cmds = _lc_segment32_with_sections([(0x9, 8)])
    facts = describe_native(
        _write(tmp_path, "a.bin", _macho32_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1))
    )["native"]
    assert facts["init_funcs"] == {"mod_init": 2, "mod_term": 0}


def test_macho_lying_init_section_size_stays_bounded(tmp_path: Path) -> None:
    # The section size is attacker-controlled; only the header field is read
    # (no pointer is followed) and the count is clamped, so a hostile image
    # cannot put a fantastical number in the facts.
    cmds = _lc_segment64_with_sections([(0x9, 1 << 40)])
    facts = describe_native(
        _write(tmp_path, "a.bin", _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1))
    )["native"]
    assert facts["init_funcs"]["mod_init"] == 8192


def test_macho_lying_nsects_reads_nothing_past_the_command(tmp_path: Path) -> None:
    # nsects is attacker-controlled too; the walk is bounded by the command's
    # own size, so a huge claim counts only the sections that actually fit.
    cmds = _lc_segment64_with_sections([(0x9, 8)], nsects=1_000_000)
    facts = describe_native(
        _write(tmp_path, "a.bin", _macho64_full(filetype=2, flags=0x4, load_cmds=cmds, ncmds=1))
    )["native"]
    assert facts["init_funcs"] == {"mod_init": 1, "mod_term": 0}


def test_macho_reads_load_commands_past_the_header_window(tmp_path: Path) -> None:
    # A dylib whose load command sits beyond the 4 KiB header window is only
    # reachable by reading the whole load-command region from the file, the way
    # the ELF reader seeks rather than working off the window alone.
    lib = "/usr/lib/libLate.dylib"
    data = _macho64_full(
        filetype=2,
        flags=0x4,  # MH_DYLDLINK
        load_cmds=_lc_filler(5000) + _lc_load_dylib(lib),
        ncmds=2,
    )
    assert len(data) > 4096  # the dylib command is past the header window
    facts = describe_native(_write(tmp_path, "big.bin", data))["native"]
    assert facts["dylibs"] == [lib]


def test_macho_universal_lists_slices(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _macho_fat(0x01000007, 0x0100000C))
    assert classify_target(str(path)) is TargetKind.NATIVE
    facts = describe_native(path)["native"]
    assert facts["format"] == "macho-universal"
    assert facts["slice_count"] == 2
    assert facts["architectures"] == ["x86-64", "arm64"]


def test_macho_universal_describes_each_slice_in_full(tmp_path: Path) -> None:
    # Every slice is a complete thin Mach-O, so the whole thin reader must
    # run per slice: the x86-64 slice here is a dynamic PIE executable with a
    # dylib, the arm64 one a plain static image -- facts one merged view (or
    # an arch list alone) could not carry.
    dylib = "/usr/lib/libSystem.B.dylib"
    x86 = _macho64_full(
        filetype=2,  # MH_EXECUTE
        flags=0x00200000 | 0x4,  # MH_PIE | MH_DYLDLINK
        load_cmds=_lc_load_dylib(dylib),
        ncmds=1,
    )
    arm = _retyped_macho(_macho64_full(filetype=6, flags=0), cputype=0x0100000C)  # MH_DYLIB
    fat = _macho_fat_with_slices([(0x01000007, x86), (0x0100000C, arm)])
    path = _write(tmp_path, "universal.bin", fat)
    facts = describe_native(path)["native"]
    assert facts["format"] == "macho-universal"
    assert facts["architectures"] == ["x86-64", "arm64"]
    first, second = facts["slices"]
    assert first["arch"] == "x86-64"
    assert first["type"] == "execute"
    assert first["pie"] is True
    assert first["dylibs"] == [dylib]
    assert second["arch"] == "arm64"
    assert second["type"] == "dylib"
    assert second["pie"] is False


def test_macho_universal_skips_a_slice_it_cannot_read(tmp_path: Path) -> None:
    # A fat_arch row pointing past the file (or at bytes that are not a thin
    # Mach-O) contributes no slice entry; the arch census still names it.
    good = _macho64_full(filetype=2, flags=0)
    raw = bytearray(_macho_fat_with_slices([(0x01000007, good), (0x0100000C, good)]))
    # Corrupt the second row's offset to point far past the end of the file.
    second_row = 8 + 20
    raw[second_row + 8 : second_row + 12] = (0x00FF_0000).to_bytes(4, "big")
    facts = describe_native(_write(tmp_path, "cut.bin", bytes(raw)))["native"]
    assert facts["architectures"] == ["x86-64", "arm64"]
    assert len(facts["slices"]) == 1
    assert facts["slices"][0]["arch"] == "x86-64"


def test_macho_universal_without_readable_slices_keeps_the_census(tmp_path: Path) -> None:
    # The legacy shape: all-zero offsets and sizes (the classifier fixture).
    # No slice can be described, so the key is absent -- not an empty list
    # pretending the file was empty.
    path = _write(tmp_path, "hollow.bin", _macho_fat(0x01000007, 0x0100000C))
    facts = describe_native(path)["native"]
    assert facts["slice_count"] == 2
    assert "slices" not in facts


def test_session_over_a_universal_binary_carries_the_slices(tmp_path: Path) -> None:
    x86 = _macho64_full(filetype=2, flags=0x00200000)
    path = _write(tmp_path, "fat.bin", _macho_fat_with_slices([(0x01000007, x86)]))
    session = SessionRegistry().create(str(path))
    native = session.metadata["native"]
    assert native["format"] == "macho-universal"
    assert native["slices"][0]["arch"] == "x86-64"
    assert native["slices"][0]["pie"] is True


def test_java_class_is_not_mistaken_for_a_universal_binary(tmp_path: Path) -> None:
    # Shares 0xCAFEBABE but the "slice count" is a Java version >= 45.
    path = _write(tmp_path, "T.class", _java_class())
    assert classify_target(str(path)) is TargetKind.PE
    assert describe_native(path) == {}


def test_non_native_returns_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", b"MZ\x90\x00 not really but not native either")
    assert describe_native(path) == {}


_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
_SHT_NOBITS_TEST = 8


class TestNativeOverlay:
    """describe_native reports data appended past the mapped image.

    The PE line has always reported its overlay -- the bytes past the last
    section, where self-extractors and droppers park payloads. The same
    question exists for ELF (past every segment, non-NOBITS section and header
    table) and Mach-O (past every segment, the symbol/string tables and the
    code signature); a native session now answers it tool-free, with absence
    meaning "nothing appended".
    """

    def test_a_fully_covered_elf_reports_no_overlay(self, tmp_path: Path) -> None:
        base = _elf64_with_dynsym([("frob", 1, 2, 1)])
        facts = describe_native(_write(tmp_path, "clean.bin", base))["native"]
        assert "overlay" not in facts

    def test_appended_bytes_read_as_the_elf_overlay(self, tmp_path: Path) -> None:
        base = _elf64_with_dynsym([("frob", 1, 2, 1)])
        path = _write(tmp_path, "padded.bin", base + b"DROPPER")
        facts = describe_native(path)["native"]
        assert facts["overlay"] == {"offset": len(base), "size": 7}

    def test_a_nobits_section_does_not_extend_the_image(self, tmp_path: Path) -> None:
        # .bss claims a huge in-memory size at the end of the file; those bytes
        # exist only at run time, so appended data must still be the overlay --
        # a reader that counted NOBITS sizes would swallow it.
        shoff = 64
        sections = _shdr64_full(0) + _shdr64_full(
            _SHT_NOBITS_TEST, sh_offset=shoff + 128, sh_size=1 << 30
        )
        base = _ehdr64(3, phoff=0, phnum=0, shoff=shoff, shnum=2) + sections
        path = _write(tmp_path, "bss.bin", base + b"PAYLOAD-X!")
        facts = describe_native(path)["native"]
        assert facts["overlay"] == {"offset": len(base), "size": 10}

    def test_a_lying_section_offset_cannot_invent_an_overlay(self, tmp_path: Path) -> None:
        # A section claiming to reach past EOF clamps to the file size: the
        # fact degrades to absent rather than reporting a negative or phantom
        # region.
        shoff = 64
        sections = _shdr64_full(0) + _shdr64_full(1, sh_offset=1 << 40, sh_size=64)
        base = _ehdr64(3, phoff=0, phnum=0, shoff=shoff, shnum=2) + sections
        facts = describe_native(_write(tmp_path, "liar.bin", base + b"tail"))["native"]
        assert "overlay" not in facts

    def test_a_header_only_elf_reports_no_overlay(self, tmp_path: Path) -> None:
        # With no program or section table at all there is nothing to anchor an
        # image end, so trailing bytes are unknowable, not an overlay claim.
        path = _write(tmp_path, "bare.bin", _elf64_le() + b"\x00" * 44 + b"trailing")
        facts = describe_native(path)["native"]
        assert "overlay" not in facts

    def test_committed_macho_fixture_reports_no_overlay(self) -> None:
        if not _MACHO_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")
        facts = describe_native(_MACHO_FIXTURE)["native"]
        assert "overlay" not in facts

    def test_appended_bytes_read_as_the_macho_overlay(self, tmp_path: Path) -> None:
        if not _MACHO_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_MACHO_FIXTURE}")
        base = _MACHO_FIXTURE.read_bytes()
        path = _write(tmp_path, "padded.macho", base + b"PAYLOAD")
        facts = describe_native(path)["native"]
        assert facts["overlay"] == {"offset": len(base), "size": 7}

    def test_macho_header_anchors_the_overlay_without_segments(self, tmp_path: Path) -> None:
        # The mach header itself declares its command region, so even with no
        # segments the image end is known and trailing bytes are the overlay.
        base = _macho64_full(filetype=2, flags=0, load_cmds=b"", ncmds=0)
        path = _write(tmp_path, "bare.macho", base + b"XY")
        facts = describe_native(path)["native"]
        assert facts["overlay"] == {"offset": len(base), "size": 2}

    def test_a_lying_macho_symtab_cannot_invent_an_overlay(self, tmp_path: Path) -> None:
        # LC_SYMTAB claiming a billion symbols clamps to the file size; the
        # trailing bytes it "covers" stop being reportable rather than the
        # walk misfiring.
        symtab = (
            (2).to_bytes(4, "little")  # LC_SYMTAB
            + (24).to_bytes(4, "little")
            + (32 + 24).to_bytes(4, "little")  # symoff: right after the command
            + (1 << 30).to_bytes(4, "little")  # nsyms: a lie
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        )
        base = _macho64_full(filetype=2, flags=0, load_cmds=symtab, ncmds=1)
        facts = describe_native(_write(tmp_path, "liar.macho", base + b"tail"))["native"]
        assert "overlay" not in facts


# ---- section-level payload census (ELF and Mach-O) ------------------------

_NESTED_PE = b"MZ" + b"\x00" * 0x60  # >= 0x40 bytes: a real DOS-stub-sized PE
_NESTED_ELF = b"\x7fELF" + b"\x00" * 0x30
_NESTED_ZIP = b"PK\x03\x04" + b"\x00" * 0x30


def _elf64_with_sections(
    sections: list[tuple[str, int, bytes]],
    *,
    nobits_names: frozenset[str] = frozenset(),
    oob_names: frozenset[str] = frozenset(),
) -> bytes:
    """A 64-bit LE ELF whose section table carries the given sections.

    Each section is ``(name, sh_type, payload)``. Layout is
    ehdr | .shstrtab | payloads | section headers, with e_shstrndx pointing at
    the trailing .shstrtab so names resolve. A name in ``nobits_names`` is
    marked SHT_NOBITS (its bytes are laid down, but the reader must treat the
    section as file-less); a name in ``oob_names`` gets a sh_offset far past
    EOF so the read is refused.
    """
    shstr = bytearray(b"\x00")
    name_off: dict[str, int] = {}
    for name, _type, _payload in sections:
        name_off[name] = len(shstr)
        shstr += name.encode() + b"\x00"
    shstrtab_name = len(shstr)
    shstr += b".shstrtab\x00"

    shstr_off = 64
    payload_off: dict[str, int] = {}
    blobs = bytearray()
    cursor = shstr_off + len(shstr)
    for name, _type, payload in sections:
        payload_off[name] = cursor
        blobs += payload
        cursor += len(payload)
    sh_off = cursor

    shdrs = bytearray(_shdr64_full(0))  # index 0: SHT_NULL
    for name, sh_type, payload in sections:
        off = 0x7000_0000 if name in oob_names else payload_off[name]
        stype = 8 if name in nobits_names else sh_type  # SHT_NOBITS override
        shdr = bytearray(_shdr64_full(stype, sh_offset=off, sh_size=len(payload)))
        shdr[0:4] = name_off[name].to_bytes(4, "little")  # sh_name
        shdrs += shdr
    shstr_shdr = bytearray(_shdr64_full(3, sh_offset=shstr_off, sh_size=len(shstr)))
    shstr_shdr[0:4] = shstrtab_name.to_bytes(4, "little")
    shdrs += shstr_shdr

    shnum = len(sections) + 2
    shstrndx = len(sections) + 1
    ehdr = bytearray(_ehdr64(2, phoff=0, phnum=0, shoff=sh_off, shnum=shnum))
    ehdr[62:64] = shstrndx.to_bytes(2, "little")  # e_shstrndx
    return bytes(ehdr) + bytes(shstr) + bytes(blobs) + bytes(shdrs)


def _macho64_with_section_payloads(sections: list[tuple[str, bytes]]) -> bytes:
    """A 64-bit Mach-O with one __DATA segment whose sections carry payloads.

    Each section is ``(sectname, payload)``; the content is appended after the
    load commands and every section header's file offset points at it, so the
    reader sniffs real file bytes. An empty ``payload`` makes a zero-length
    (S_ZEROFILL-shaped) section with no file bytes.
    """
    nsects = len(sections)
    seg_total = 72 + 80 * nsects
    data_start = 32 + seg_total
    offsets: list[int] = []
    blobs = bytearray()
    cursor = data_start
    for _name, payload in sections:
        offsets.append(cursor if payload else 0)
        blobs += payload
        cursor += len(payload)

    cmd = bytearray(72)
    cmd[0:4] = (0x19).to_bytes(4, "little")  # LC_SEGMENT_64
    cmd[4:8] = seg_total.to_bytes(4, "little")
    cmd[8:24] = b"__DATA".ljust(16, b"\x00")
    cmd[64:68] = nsects.to_bytes(4, "little")
    body = bytearray()
    for (name, payload), off in zip(sections, offsets, strict=True):
        sect = bytearray(80)
        sect[0:16] = name.encode().ljust(16, b"\x00")[:16]
        sect[16:32] = b"__DATA".ljust(16, b"\x00")
        sect[40:48] = len(payload).to_bytes(8, "little")  # size
        sect[48:52] = off.to_bytes(4, "little")  # offset
        body += sect
    header = _macho64_full(filetype=2, flags=0, load_cmds=bytes(cmd) + bytes(body), ncmds=1)
    assert len(header) == data_start
    return header + bytes(blobs)


class TestElfSectionPayloads:
    """describe_native lists ELF sections whose bytes open with executable magic.

    The native dropper's stash: a nested PE it writes out for a Windows drop, an
    ELF loader, a zipped bundle -- each parked in a custom section. Every flag
    names the section it hid under, the sniffed kind and the byte size; ordinary
    code/data sections and a file-less .bss are never listed.
    """

    def test_a_clean_object_lists_nothing(self, tmp_path: Path) -> None:
        data = _elf64_with_sections([(".text", 1, b"\x90" * 32), (".comment", 1, b"GCC: 13")])
        facts = describe_native(_write(tmp_path, "clean.elf", data))["native"]
        assert facts["section_payload_count"] == 0
        assert facts["section_payloads"] == []

    def test_each_planted_kind_reads_under_its_section_name(self, tmp_path: Path) -> None:
        data = _elf64_with_sections(
            [
                (".payload", 1, _NESTED_PE),
                (".loader", 1, _NESTED_ELF),
                (".bundle", 1, _NESTED_ZIP),
                (".rodata", 1, b"a benign read-only string"),
            ]
        )
        facts = describe_native(_write(tmp_path, "dropper.elf", data))["native"]
        assert facts["section_payload_count"] == 3
        listed = {e["section"]: e["kind"] for e in facts["section_payloads"]}
        assert listed == {".payload": "pe", ".loader": "elf", ".bundle": "zip"}
        pe = next(e for e in facts["section_payloads"] if e["kind"] == "pe")
        assert pe["size"] == len(_NESTED_PE)

    def test_a_nobits_section_is_not_file_backed(self, tmp_path: Path) -> None:
        # .bss occupies no file bytes; even if the on-disk bytes at its declared
        # offset are ELF magic, the reader must not read them as a payload.
        data = _elf64_with_sections(
            [(".bss", 1, _NESTED_ELF)], nobits_names=frozenset({".bss"})
        )
        facts = describe_native(_write(tmp_path, "bss.elf", data))["native"]
        assert facts["section_payload_count"] == 0

    def test_a_section_offset_past_eof_is_skipped(self, tmp_path: Path) -> None:
        data = _elf64_with_sections(
            [(".payload", 1, _NESTED_PE)], oob_names=frozenset({".payload"})
        )
        facts = describe_native(_write(tmp_path, "oob.elf", data))["native"]
        assert facts["section_payload_count"] == 0

    def test_prose_opening_with_mz_is_not_an_executable(self, tmp_path: Path) -> None:
        data = _elf64_with_sections([(".data", 1, b"MZ are my initials")])
        facts = describe_native(_write(tmp_path, "prose.elf", data))["native"]
        assert facts["section_payload_count"] == 0

    def test_the_list_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        sections = [(f".s{i:03d}", 1, _NESTED_ELF) for i in range(80)]
        facts = describe_native(_write(tmp_path, "many.elf", _elf64_with_sections(sections)))[
            "native"
        ]
        assert facts["section_payload_count"] == 80
        assert len(facts["section_payloads"]) == 64

    def test_a_header_only_elf_omits_the_census(self, tmp_path: Path) -> None:
        # No section table to walk (like the `stripped` fact): the census is
        # omitted rather than reported as an empty, misleading zero.
        facts = describe_native(_write(tmp_path, "hdr.elf", _elf64_le()))["native"]
        assert "section_payloads" not in facts
        assert "section_payload_count" not in facts


class TestHighEntropySections:
    """describe_native flags near-random sections -- the packed-payload tell.

    Compressed or encrypted bytes measure near 8 bits per byte; code and text
    sit well below. The flag is what the magic-byte payload census cannot
    raise: an encrypted stage two opens with no magic at all. Sections too
    small for the measure to mean anything are skipped, and an empty list is
    a real "nothing packed here" answer.
    """

    def test_a_uniform_byte_spread_measures_eight_and_flags(self, tmp_path: Path) -> None:
        # Every byte value equally often: exactly 8.0 bits per byte, the
        # deterministic stand-in for an encrypted payload.
        data = _elf64_with_sections(
            [(".text", 1, b"\x90" * 512), (".blob", 1, bytes(range(256)) * 4)]
        )
        facts = describe_native(_write(tmp_path, "packed.elf", data))["native"]
        assert facts["high_entropy_sections"] == [
            {"section": ".blob", "entropy": 8.0, "size": 1024}
        ]

    def test_a_compressed_payload_flags_like_an_encrypted_one(self, tmp_path: Path) -> None:
        import zlib

        # A real deflate stream big enough for the measure to settle: what a
        # packer's compressed payload actually looks like on disk.
        corpus = " ".join(f"record {i} value {i * i}" for i in range(20000)).encode()
        payload = zlib.compress(corpus, level=9)
        data = _elf64_with_sections([(".stash", 1, payload)])
        facts = describe_native(_write(tmp_path, "stash.elf", data))["native"]
        (flag,) = facts["high_entropy_sections"]
        assert flag["section"] == ".stash"
        assert flag["entropy"] >= 7.2

    def test_ordinary_code_and_text_stay_unflagged(self, tmp_path: Path) -> None:
        data = _elf64_with_sections(
            [(".text", 1, b"\x90\x48\x89\xe5\xc3" * 200), (".rodata", 1, b"hello world " * 100)]
        )
        facts = describe_native(_write(tmp_path, "plain.elf", data))["native"]
        assert facts["high_entropy_sections"] == []

    def test_a_section_below_the_size_floor_is_not_measured(self, tmp_path: Path) -> None:
        # 128 near-random bytes: too few samples for the measure to mean
        # anything, so no flag regardless of the spread.
        data = _elf64_with_sections([(".tiny", 1, bytes(range(128)))])
        facts = describe_native(_write(tmp_path, "tiny.elf", data))["native"]
        assert facts["high_entropy_sections"] == []

    def test_a_nobits_section_is_not_measured(self, tmp_path: Path) -> None:
        data = _elf64_with_sections(
            [(".bss", 1, bytes(range(256)) * 4)], nobits_names=frozenset({".bss"})
        )
        facts = describe_native(_write(tmp_path, "bss.elf", data))["native"]
        assert facts["high_entropy_sections"] == []

    def test_macho_flags_its_near_random_section(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads(
            [("__text", b"\x90" * 512), ("__blob", bytes(range(256)) * 4)]
        )
        facts = describe_native(_write(tmp_path, "packed.macho", data))["native"]
        assert facts["high_entropy_sections"] == [
            {"section": "__blob", "entropy": 8.0, "size": 1024}
        ]

    def test_macho_ordinary_sections_stay_unflagged(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads([("__text", b"\x90\x48\x89\xe5\xc3" * 200)])
        facts = describe_native(_write(tmp_path, "plain.macho", data))["native"]
        assert facts["high_entropy_sections"] == []


class TestDebugInfo:
    """describe_native reports the DWARF debug-info census for ELF and Mach-O.

    DWARF (``.debug_*`` / ``__debug_*``) is what a ``-g`` build ships and a
    release build does not: the native pair to the PE and .NET PDB facts and
    the WASM name section. ``present`` is false with an empty list for a
    stripped or never-debug build -- a real answer, always reported when a
    section table exists.
    """

    def test_elf_reads_the_dwarf_sections_and_their_size(self, tmp_path: Path) -> None:
        data = _elf64_with_sections(
            [
                (".text", 1, b"\x90" * 32),
                (".debug_info", 1, b"\x00" * 128),
                (".debug_line", 1, b"\x00" * 64),
                (".debug_abbrev", 1, b"\x00" * 48),
            ]
        )
        facts = describe_native(_write(tmp_path, "g.elf", data))["native"]
        assert facts["debug_info"] == {
            "present": True,
            "sections": ["debug_abbrev", "debug_info", "debug_line"],
            "size": 240,
        }

    def test_elf_compressed_zdebug_folds_to_the_same_name(self, tmp_path: Path) -> None:
        # The old GNU compressed spelling ``.zdebug_info`` names the same
        # logical section as ``.debug_info``; the census folds them together.
        data = _elf64_with_sections([(".zdebug_info", 1, b"\x00" * 100)])
        facts = describe_native(_write(tmp_path, "z.elf", data))["native"]
        assert facts["debug_info"] == {
            "present": True,
            "sections": ["debug_info"],
            "size": 100,
        }

    def test_elf_without_debug_sections_reports_absent(self, tmp_path: Path) -> None:
        data = _elf64_with_sections([(".text", 1, b"\x90" * 64), (".rodata", 1, b"hi" * 20)])
        facts = describe_native(_write(tmp_path, "rel.elf", data))["native"]
        assert facts["debug_info"] == {"present": False, "sections": [], "size": 0}

    def test_a_section_merely_named_debugger_is_not_dwarf(self, tmp_path: Path) -> None:
        # DWARF sections are ``debug_<unit>``; a section called ``.debugger``
        # (no underscore after ``debug``) is not one.
        data = _elf64_with_sections([(".debugger", 1, b"\x00" * 300)])
        facts = describe_native(_write(tmp_path, "trap.elf", data))["native"]
        assert facts["debug_info"] == {"present": False, "sections": [], "size": 0}

    def test_macho_reads_its_dwarf_segment_sections(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads(
            [
                ("__text", b"\x90" * 32),
                ("__debug_info", b"\x00" * 96),
                ("__debug_line", b"\x00" * 40),
            ]
        )
        facts = describe_native(_write(tmp_path, "g.macho", data))["native"]
        assert facts["debug_info"] == {
            "present": True,
            "sections": ["debug_info", "debug_line"],
            "size": 136,
        }

    def test_macho_without_dwarf_reports_absent(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads([("__text", b"\x90" * 64)])
        facts = describe_native(_write(tmp_path, "rel.macho", data))["native"]
        assert facts["debug_info"] == {"present": False, "sections": [], "size": 0}


def _property_note(entries: list[tuple[int, bytes]], align: int = 8) -> bytes:
    # NT_GNU_PROPERTY_TYPE_0 (type 5): an array of {pr_type, pr_datasz,
    # pr_data} entries, each padded so the next starts word-aligned.
    body = b""
    for pr_type, data in entries:
        body += pr_type.to_bytes(4, "little") + len(data).to_bytes(4, "little") + data
        body += b"\x00" * (-len(body) % align)
    return _elf_note(5, b"GNU", body)


class TestElfCfProtection:
    """describe_native reads the branch-protection posture off the property note.

    The ELF pair to PE's cfg bit: gcc -fcf-protection stamps IBT/SHSTK on
    x86, -mbranch-protection stamps BTI/PAC on arm64, and readelf -n prints
    the same names. An image with no feature entry -- or no property note at
    all -- was built without the protection, so an empty list is that real
    answer, present whenever the program headers parsed.
    """

    def test_ibt_and_shstk_read_from_the_x86_feature_mask(self, tmp_path: Path) -> None:
        note = _property_note([(0xC0000002, (3).to_bytes(4, "little"))])
        facts = describe_native(_write(tmp_path, "cet.elf", _elf64_with_notes(note)))["native"]
        assert facts["cf_protection"] == ["ibt", "shstk"]

    def test_a_branch_only_build_reads_ibt_alone(self, tmp_path: Path) -> None:
        note = _property_note([(0xC0000002, (1).to_bytes(4, "little"))])
        facts = describe_native(_write(tmp_path, "ibt.elf", _elf64_with_notes(note)))["native"]
        assert facts["cf_protection"] == ["ibt"]

    def test_bti_and_pac_read_from_the_aarch64_mask(self, tmp_path: Path) -> None:
        note = _property_note([(0xC0000000, (3).to_bytes(4, "little"))])
        facts = describe_native(_write(tmp_path, "bp.elf", _elf64_with_notes(note)))["native"]
        assert facts["cf_protection"] == ["bti", "pac"]

    def test_a_note_with_no_feature_entry_reads_empty(self, tmp_path: Path) -> None:
        # gcc -fcf-protection=none still writes a property note (ISA-needed,
        # pr_type 0xc0008002): a note without the feature mask is unprotected.
        note = _property_note([(0xC0008002, (1).to_bytes(4, "little"))])
        facts = describe_native(_write(tmp_path, "none.elf", _elf64_with_notes(note)))["native"]
        assert facts["cf_protection"] == []

    def test_no_property_note_at_all_reads_empty(self, tmp_path: Path) -> None:
        facts = describe_native(
            _write(tmp_path, "old.elf", _elf64_with_notes(_abi_note(0, 3, 2, 0)))
        )["native"]
        assert facts["cf_protection"] == []

    def test_the_feature_mask_is_read_past_a_padded_entry(self, tmp_path: Path) -> None:
        # A 4-byte property on ELF64 pads to 8 before the next entry; the
        # feature mask sitting second proves the walk honours the alignment.
        note = _property_note(
            [
                (0xC0008002, (1).to_bytes(4, "little")),
                (0xC0000002, (2).to_bytes(4, "little")),
            ]
        )
        facts = describe_native(_write(tmp_path, "pad.elf", _elf64_with_notes(note)))["native"]
        assert facts["cf_protection"] == ["shstk"]

    def test_unknown_feature_bits_are_not_named(self, tmp_path: Path) -> None:
        # Bit 2 (LAM_U48 and friends) has no census name; only the recognised
        # features are reported, never an invented label.
        note = _property_note([(0xC0000002, (4 | 1).to_bytes(4, "little"))])
        facts = describe_native(_write(tmp_path, "lam.elf", _elf64_with_notes(note)))["native"]
        assert facts["cf_protection"] == ["ibt"]


class TestUrlCensus:
    """describe_native reports the endpoint literals baked into the image.

    "Who does it talk to?" is the first triage question, and a C string in
    .rodata answers it before any tool runs. Only scheme-prefixed URLs count
    (bare hostnames drown in false positives), duplicates record once, and
    the cleartext count is the binary's own uses-cleartext-traffic answer.
    GNU ``strings`` surfaces the same literals, so the gate cross-checks it.
    """

    def test_ascii_literals_are_read_with_exact_counts(self, tmp_path: Path) -> None:
        data = (
            _elf64_le()
            + b"\x00connect to https://api.example.com/v1\x00"
            + b"fallback http://plain.example/beacon\x00"
            + b"again https://api.example.com/v1\x00"  # a duplicate records once
        )
        facts = describe_native(_write(tmp_path, "urls.elf", data))["native"]
        assert facts["urls"] == [
            "https://api.example.com/v1",
            "http://plain.example/beacon",
        ]
        assert facts["url_count"] == 2
        assert facts["cleartext_url_count"] == 1

    def test_wide_literals_read_the_same_as_narrow_ones(self, tmp_path: Path) -> None:
        # UTF-16LE is how Windows wide strings and the .NET #US heap store
        # literals; the same endpoint must not hide behind the encoding.
        wide = "https://wide.example/path".encode("utf-16-le")
        data = _elf64_le() + b"\x00\x00" + wide + b"\x00\x00"
        facts = describe_native(_write(tmp_path, "wide.elf", data))["native"]
        assert facts["urls"] == ["https://wide.example/path"]

    def test_a_url_split_across_scan_chunks_reads_once_and_whole(self, tmp_path: Path) -> None:
        # The scanner reads in 1 MiB chunks; a literal straddling the boundary
        # must come back whole and once -- never as a truncated ghost too.
        url = b"http://boundary.example/" + b"a" * 64
        data = _elf64_le()
        data += b"\x00" * ((1 << 20) - len(data) - 10) + url + b"\x00" * 32
        facts = describe_native(_write(tmp_path, "split.elf", data))["native"]
        assert facts["urls"] == [url.decode("ascii")]
        assert facts["url_count"] == 1

    def test_xml_namespace_identifiers_are_not_endpoints(self, tmp_path: Path) -> None:
        # A namespace URI names a format, not a listener; leaving them in
        # would put a constant cleartext "endpoint" on virtually every image.
        data = (
            _elf64_le()
            + b"\x00http://schemas.android.com/apk/res/android\x00"
            + b"http://www.w3.org/2000/xmlns/\x00"
            + b"http://real.example/c2\x00"
        )
        facts = describe_native(_write(tmp_path, "ns.elf", data))["native"]
        assert facts["urls"] == ["http://real.example/c2"]
        assert facts["cleartext_url_count"] == 1

    def test_an_image_without_urls_reports_an_empty_census(self, tmp_path: Path) -> None:
        facts = describe_native(_write(tmp_path, "plain.elf", _elf64_le()))["native"]
        assert facts["urls"] == []
        assert facts["url_count"] == 0
        assert facts["cleartext_url_count"] == 0

    def test_the_listed_sample_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        blob = b"\x00".join(b"https://host%d.example/x" % i for i in range(40))
        facts = describe_native(_write(tmp_path, "many.elf", _elf64_le() + b"\x00" + blob))[
            "native"
        ]
        assert facts["url_count"] == 40
        assert len(facts["urls"]) == 32

    def test_a_macho_image_gets_the_same_census(self, tmp_path: Path) -> None:
        data = _macho64_le() + b"\x00" * 24 + b"ws://sock.example/live\x00"
        facts = describe_native(_write(tmp_path, "urls.macho", data))["native"]
        assert facts["urls"] == ["ws://sock.example/live"]
        assert facts["cleartext_url_count"] == 1


class TestElfToolchain:
    """describe_native reports .comment compiler records -- the ELF toolchain.

    Every compiler that contributed objects to the link appends one
    NUL-terminated record; the fact is the pair to the WASM producers section,
    a Mach-O build-tool entry and a PE Rich header, and reads exactly what
    ``readelf -p .comment`` prints. Absent stays absent: an image without the
    section (or whose .comment is not file-backed) records no provenance.
    """

    def test_comment_records_read_in_link_order(self, tmp_path: Path) -> None:
        comment = b"GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0\x00clang version 17.0.6\x00"
        data = _elf64_with_sections([(".text", 1, b"\x90" * 8), (".comment", 1, comment)])
        facts = describe_native(_write(tmp_path, "cc.elf", data))["native"]
        assert facts["toolchain"] == [
            "GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0",
            "clang version 17.0.6",
        ]

    def test_repeated_records_dedupe_to_one(self, tmp_path: Path) -> None:
        # Every object file repeats its compiler's record; the link keeps them
        # all, the fact reports each toolchain once.
        comment = b"GCC: (GNU) 12.3.0\x00" * 5
        data = _elf64_with_sections([(".comment", 1, comment)])
        facts = describe_native(_write(tmp_path, "dup.elf", data))["native"]
        assert facts["toolchain"] == ["GCC: (GNU) 12.3.0"]

    def test_an_elf_without_comment_records_no_provenance(self, tmp_path: Path) -> None:
        data = _elf64_with_sections([(".text", 1, b"\x90" * 8)])
        facts = describe_native(_write(tmp_path, "bare.elf", data))["native"]
        assert "toolchain" not in facts

    def test_a_nobits_comment_is_not_file_backed(self, tmp_path: Path) -> None:
        data = _elf64_with_sections(
            [(".comment", 1, b"GCC: (GNU) 12.3.0\x00")], nobits_names=frozenset({".comment"})
        )
        facts = describe_native(_write(tmp_path, "nobits.elf", data))["native"]
        assert "toolchain" not in facts

    def test_the_record_list_is_bounded(self, tmp_path: Path) -> None:
        comment = b"".join(f"compiler {i:02d}\x00".encode() for i in range(20))
        data = _elf64_with_sections([(".comment", 1, comment)])
        facts = describe_native(_write(tmp_path, "many.elf", data))["native"]
        assert len(facts["toolchain"]) == 16  # _ELF_MAX_TOOLCHAIN


def _debuglink_blob(filename: bytes, crc: int, *, drop_nul: bool = False) -> bytes:
    """A ``.gnu_debuglink`` payload: name, NUL, pad to 4, then the CRC32."""
    body = bytearray(filename)
    if not drop_nul:
        body += b"\x00"
        while len(body) % 4:
            body += b"\x00"
    return bytes(body) + crc.to_bytes(4, "little")


class TestElfDebugLink:
    """describe_native reports .gnu_debuglink -- where the stripped symbols went.

    The ELF pair to the PE pdb-path fact: the strip pipeline leaves the
    separate debug file's basename plus a CRC32 of that file's bytes, and gdb
    re-finds the symbols by both. Absent stays absent -- an image that never
    went through objcopy --add-gnu-debuglink has nothing to report.
    """

    def test_the_record_reads_filename_and_crc(self, tmp_path: Path) -> None:
        blob = _debuglink_blob(b"app.debug", 0xDEADBEEF)
        data = _elf64_with_sections([(".text", 1, b"\x90" * 8), (".gnu_debuglink", 1, blob)])
        facts = describe_native(_write(tmp_path, "linked.elf", data))["native"]
        assert facts["debug_link"] == {"filename": "app.debug", "crc32": "deadbeef"}

    def test_padding_between_name_and_crc_is_stepped_over(self, tmp_path: Path) -> None:
        # A 3-char name needs no pad byte after its NUL; a 4-char name needs
        # three. Both shapes must land on the same 4-aligned CRC slot.
        for name in (b"abc", b"abcd"):
            blob = _debuglink_blob(name, 0x0BADF00D)
            data = _elf64_with_sections([(".gnu_debuglink", 1, blob)])
            facts = describe_native(_write(tmp_path, f"{name.decode()}.elf", data))["native"]
            assert facts["debug_link"] == {
                "filename": name.decode(),
                "crc32": "0badf00d",
            }

    def test_an_elf_without_the_section_records_nothing(self, tmp_path: Path) -> None:
        data = _elf64_with_sections([(".text", 1, b"\x90" * 8)])
        facts = describe_native(_write(tmp_path, "bare.elf", data))["native"]
        assert "debug_link" not in facts

    def test_a_record_without_a_nul_is_malformed(self, tmp_path: Path) -> None:
        # No terminator means no way to tell name from CRC; fail closed.
        blob = _debuglink_blob(b"noterminator", 0, drop_nul=True)
        data = _elf64_with_sections([(".gnu_debuglink", 1, blob)])
        facts = describe_native(_write(tmp_path, "nonul.elf", data))["native"]
        assert "debug_link" not in facts

    def test_a_record_too_short_for_the_crc_is_malformed(self, tmp_path: Path) -> None:
        data = _elf64_with_sections([(".gnu_debuglink", 1, b"app\x00")])
        facts = describe_native(_write(tmp_path, "short.elf", data))["native"]
        assert "debug_link" not in facts


class TestMachoSectionPayloads:
    """describe_native lists Mach-O sections whose bytes open with executable magic.

    The Mach-O twin of the ELF section census: a dropper hides its stage two in
    a ``__DATA,__payload`` it writes out and runs. Each flag names the section,
    the sniffed kind and the byte size; a benign section and a file-less
    (zero-offset) section are never listed.
    """

    def test_each_planted_kind_reads_under_its_section_name(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads(
            [
                ("__payload", _NESTED_PE),
                ("__loader", _NESTED_ELF),
                ("__bundle", _NESTED_ZIP),
                ("__cstring", b"a benign C string table"),
            ]
        )
        facts = describe_native(_write(tmp_path, "dropper.macho", data))["native"]
        assert facts["section_payload_count"] == 3
        listed = {e["section"]: e["kind"] for e in facts["section_payloads"]}
        assert listed == {"__payload": "pe", "__loader": "elf", "__bundle": "zip"}
        pe = next(e for e in facts["section_payloads"] if e["kind"] == "pe")
        assert pe["size"] == len(_NESTED_PE)

    def test_a_clean_macho_lists_nothing(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads([("__text", b"\x90" * 32)])
        facts = describe_native(_write(tmp_path, "clean.macho", data))["native"]
        assert facts["section_payload_count"] == 0
        assert facts["section_payloads"] == []

    def test_a_zerofill_section_with_no_file_bytes_is_skipped(self, tmp_path: Path) -> None:
        # A zero-length section header (offset 0) has no file content; it must
        # not be read as opening with whatever byte happens to sit at offset 0.
        data = _macho64_with_section_payloads([("__bss", b""), ("__payload", _NESTED_ELF)])
        facts = describe_native(_write(tmp_path, "zf.macho", data))["native"]
        assert facts["section_payload_count"] == 1
        assert facts["section_payloads"][0]["section"] == "__payload"

    def test_prose_opening_with_mz_is_not_an_executable(self, tmp_path: Path) -> None:
        data = _macho64_with_section_payloads([("__data", b"MZ, a monogram")])
        facts = describe_native(_write(tmp_path, "prose.macho", data))["native"]
        assert facts["section_payload_count"] == 0

    def test_the_list_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        sections = [(f"__s{i:03d}", _NESTED_ELF) for i in range(80)]
        facts = describe_native(
            _write(tmp_path, "many.macho", _macho64_with_section_payloads(sections))
        )["native"]
        assert facts["section_payload_count"] == 80
        assert len(facts["section_payloads"]) == 64


def test_session_opens_over_a_native_binary(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_le())
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.NATIVE
    assert session.architecture is None
    assert session.metadata["native"]["arch"] == "x86-64"
    # The binary is still reachable for radare2/Ghidra/frida...
    assert session.require_binary() == path
    # ...but the PE-only debuggers refuse it like any other non-PE session.
    with pytest.raises(TargetMismatch):
        session.require_pe()


def _uvarint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _go_buildinfo_blob(
    version: str, mod_text: str | None, *, flags: int = 0x02, ptr_size: int = 8
) -> bytes:
    """A Go build-info blob in the inline layout, mirroring the linker's output.

    14-byte magic, a ptrSize byte and a flags byte, then 16 reserved bytes
    (the legacy pointer slots the inline format ignores) before the
    varint-length-prefixed version and module strings. ``mod_text`` is
    wrapped in the two 16-byte sentinels the runtime uses to bracket the
    module block; None emits an empty module string.
    """
    blob = bytearray(b"\xff Go buildinf:")
    blob.append(ptr_size)
    blob.append(flags)
    blob += b"\x00" * 16  # reserved: offset 16..31
    blob += _uvarint(len(version)) + version.encode()
    if mod_text is None:
        blob += _uvarint(0)
    else:
        sentinel = bytes(range(16))
        wrapped = sentinel + mod_text.encode() + sentinel
        blob += _uvarint(len(wrapped)) + wrapped
    return bytes(blob)


_GO_MOD_TEXT = (
    "path\texample.com/tool\n"
    "mod\texample.com/tool\t(devel)\t\n"
    "build\t-buildmode=exe\n"
    "build\tGOOS=linux\n"
    "build\tCGO_ENABLED=0\n"
)


class TestGoBuildInfo:
    """_go_build_info reads the ``.go.buildinfo`` stamp, cross-format.

    The self-declared provenance of a Go binary -- toolchain version, module
    path and build settings -- the same fact ``go version -m`` prints. The
    inline layout is identical in an ELF, a Mach-O and a PE, so the reader
    scans for the magic and decodes it the same way regardless of container.
    """

    def test_a_full_inline_stamp_decodes_every_field(self, tmp_path: Path) -> None:
        path = tmp_path / "stamp.bin"
        path.write_bytes(b"\x00" * 64 + _go_buildinfo_blob("go1.22.2", _GO_MOD_TEXT))
        assert _go_build_info(path) == {
            "go": {
                "version": "go1.22.2",
                "path": "example.com/tool",
                "main_module": "example.com/tool",
                "main_module_version": "(devel)",
                "settings": {
                    "-buildmode": "exe",
                    "GOOS": "linux",
                    "CGO_ENABLED": "0",
                },
            }
        }

    def test_an_empty_module_block_reports_version_only(self, tmp_path: Path) -> None:
        path = tmp_path / "veronly.bin"
        path.write_bytes(_go_buildinfo_blob("go1.21.0", None))
        assert _go_build_info(path) == {"go": {"version": "go1.21.0"}}

    def test_the_legacy_pointer_format_is_not_read(self, tmp_path: Path) -> None:
        # flags without the 0x2 inline bit is the pre-1.18 pointer layout,
        # which this reader does not follow: absence, not a guess.
        path = tmp_path / "legacy.bin"
        path.write_bytes(_go_buildinfo_blob("go1.16", _GO_MOD_TEXT, flags=0x00))
        assert _go_build_info(path) == {}

    def test_a_coincidental_magic_without_a_go_version_is_rejected(self, tmp_path: Path) -> None:
        # The magic can in principle appear in data; a version string that is
        # not a "go" toolchain string is the sanity check that rejects it.
        path = tmp_path / "coincidence.bin"
        path.write_bytes(_go_buildinfo_blob("notgo-1.0", None))
        assert _go_build_info(path) == {}

    def test_a_truncated_version_varint_fails_closed(self, tmp_path: Path) -> None:
        # The length says 200 bytes but only a few follow: the read is
        # bounded and yields nothing rather than running off the end.
        blob = bytearray(b"\xff Go buildinf:")
        blob += bytes([8, 0x02]) + b"\x00" * 16
        blob += _uvarint(200) + b"go1."
        path = tmp_path / "cut.bin"
        path.write_bytes(bytes(blob))
        assert _go_build_info(path) == {}

    def test_a_file_without_the_stamp_reads_absent(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.bin"
        path.write_bytes(b"not a go binary at all" * 16)
        assert _go_build_info(path) == {}

    def test_the_settings_map_is_bounded(self, tmp_path: Path) -> None:
        many = "".join(f"build\tK{i}=v{i}\n" for i in range(200))
        path = tmp_path / "many.bin"
        path.write_bytes(_go_buildinfo_blob("go1.22.2", "path\tx\n" + many))
        settings = _go_build_info(path)["go"]["settings"]
        assert len(settings) == 64  # _GO_MAX_SETTINGS

    def test_session_over_a_go_elf_carries_the_stamp(self, tmp_path: Path) -> None:
        # A real ELF header so describe_native produces facts, with the Go
        # stamp appended where the reader's whole-file scan finds it -- the
        # facts and the go block must both land on the native metadata.
        data = _elf64_le() + b"\x00" * 64 + _go_buildinfo_blob("go1.22.2", _GO_MOD_TEXT)
        path = _write(tmp_path, "go.elf", data)
        session = SessionRegistry().create(str(path))
        native = session.metadata["native"]
        assert native["format"] == "elf"
        assert native["go"]["version"] == "go1.22.2"
        assert native["go"]["main_module"] == "example.com/tool"


def _elf64_with_entry_owner(entry: int, sections: list[tuple[str, int, int, int]]) -> bytes:
    """A 64-bit LE ELF with ``e_entry`` set and an addressed section table.

    Each section is ``(name, sh_addr, sh_size, sh_flags)`` -- SHT_PROGBITS
    with no file payload, since the entry-owner lookup reads only each
    section's address span and ALLOC flag, plus the name via .shstrtab.
    """
    shstr = bytearray(b"\x00")
    name_off: dict[str, int] = {}
    for name, _addr, _size, _flags in sections:
        name_off[name] = len(shstr)
        shstr += name.encode() + b"\x00"
    shstrtab_name = len(shstr)
    shstr += b".shstrtab\x00"
    shstr_off = 64
    sh_off = shstr_off + len(shstr)
    shdrs = bytearray(_shdr64_full(0))  # index 0: SHT_NULL
    for name, addr, size, flags in sections:
        shdr = bytearray(_shdr64_full(1, sh_size=size))
        shdr[0:4] = name_off[name].to_bytes(4, "little")
        shdr[8:16] = flags.to_bytes(8, "little")  # sh_flags
        shdr[16:24] = addr.to_bytes(8, "little")  # sh_addr
        shdrs += shdr
    shstr_shdr = bytearray(_shdr64_full(3, sh_offset=shstr_off, sh_size=len(shstr)))
    shstr_shdr[0:4] = shstrtab_name.to_bytes(4, "little")
    shdrs += shstr_shdr
    ehdr = bytearray(
        _ehdr64(2, phoff=0, phnum=0, shoff=sh_off, shnum=len(sections) + 2, entry=entry)
    )
    ehdr[62:64] = (len(sections) + 1).to_bytes(2, "little")  # e_shstrndx
    return bytes(ehdr) + bytes(shstr) + bytes(shdrs)


def _lc_segment64_with_named_sections(
    vmaddr: int, fileoff: int, filesize: int, sections: list[tuple[str, int, int]]
) -> bytes:
    """An LC_SEGMENT_64 whose trailing section_64 rows carry (name, offset, size)."""
    nsects = len(sections)
    cmd = bytearray(72 + 80 * nsects)
    cmd[0:4] = (0x19).to_bytes(4, "little")  # LC_SEGMENT_64
    cmd[4:8] = len(cmd).to_bytes(4, "little")
    cmd[8:24] = b"__TEXT".ljust(16, b"\x00")
    cmd[24:32] = vmaddr.to_bytes(8, "little")
    cmd[32:40] = (0x1000).to_bytes(8, "little")  # vmsize
    cmd[40:48] = fileoff.to_bytes(8, "little")
    cmd[48:56] = filesize.to_bytes(8, "little")
    cmd[64:68] = nsects.to_bytes(4, "little")
    for i, (name, offset, size) in enumerate(sections):
        at = 72 + 80 * i
        cmd[at : at + 16] = name.encode().ljust(16, b"\x00")
        cmd[at + 16 : at + 32] = b"__TEXT".ljust(16, b"\x00")
        cmd[at + 40 : at + 48] = size.to_bytes(8, "little")
        cmd[at + 48 : at + 52] = offset.to_bytes(4, "little")
    return bytes(cmd)


class TestEntrySection:
    """describe_native names the section that owns the entry point.

    The first executed byte's home: ".text"/"__text" is the boring answer a
    linker emits, a packer stub's own section (UPX1) the classic anomaly, and
    None -- no section table, or no allocated section claiming the address --
    is itself a triage fact. Reported only next to an entry, for ELF (e_entry
    against sh_addr spans of ALLOC sections) and Mach-O (LC_MAIN's entryoff
    against section file spans).
    """

    def test_an_elf_entry_inside_text_names_text(self, tmp_path: Path) -> None:
        data = _elf64_with_entry_owner(
            0x401080,
            [(".rodata", 0x400000, 0x100, 0x2), (".text", 0x401000, 0x200, 0x6)],
        )
        facts = describe_native(_write(tmp_path, "plain.elf", data))["native"]
        assert facts["entry"] == 0x401080
        assert facts["entry_section"] == ".text"

    def test_a_non_alloc_section_cannot_claim_the_entry(self, tmp_path: Path) -> None:
        # Same address span, but the section is not mapped (no SHF_ALLOC):
        # what covers the entry on disk does not cover it in memory.
        data = _elf64_with_entry_owner(0x401080, [(".debug_fake", 0x401000, 0x200, 0x0)])
        facts = describe_native(_write(tmp_path, "unmapped.elf", data))["native"]
        assert facts["entry_section"] is None

    def test_an_entry_outside_every_section_reads_none(self, tmp_path: Path) -> None:
        data = _elf64_with_entry_owner(0x999000, [(".text", 0x401000, 0x200, 0x6)])
        facts = describe_native(_write(tmp_path, "dangling.elf", data))["native"]
        assert facts["entry_section"] is None

    def test_an_elf_without_a_section_table_reads_none(self, tmp_path: Path) -> None:
        # sstrip'd or packed ELFs drop the section table entirely; the entry
        # still exists but no section can claim it -- None, honestly.
        data = _ehdr64(2, phoff=0, phnum=0, shoff=0, shnum=0, entry=0x1000)
        facts = describe_native(_write(tmp_path, "bare.elf", data))["native"]
        assert facts["entry"] == 0x1000
        assert facts["entry_section"] is None

    def test_an_elf_without_an_entry_carries_no_owner_fact(self, tmp_path: Path) -> None:
        data = _elf64_with_entry_owner(0, [(".text", 0x401000, 0x200, 0x6)])
        facts = describe_native(_write(tmp_path, "solib.elf", data))["native"]
        assert "entry" not in facts
        assert "entry_section" not in facts

    def test_a_macho_entry_inside_text_names_text(self, tmp_path: Path) -> None:
        seg = _lc_segment64_with_named_sections(
            0x100000000, 0, 0x1000, [("__stubs", 0xE00, 0x100), ("__text", 0xF00, 0x100)]
        )
        cmds = seg + _lc_main(0xF80)
        data = _macho64_full(2, 0, cmds, ncmds=2)
        facts = describe_native(_write(tmp_path, "plain.macho", data))["native"]
        assert facts["entry"] == 0x100000F80
        assert facts["entry_section"] == "__text"

    def test_a_macho_entry_between_sections_reads_none(self, tmp_path: Path) -> None:
        # The segment covers the offset but no section does: the gap between
        # mapped sections is exactly where a shim stub would hide.
        seg = _lc_segment64_with_named_sections(0x100000000, 0, 0x1000, [("__text", 0xF00, 0x100)])
        cmds = seg + _lc_main(0x800)
        data = _macho64_full(2, 0, cmds, ncmds=2)
        facts = describe_native(_write(tmp_path, "gap.macho", data))["native"]
        assert facts["entry"] == 0x100000800
        assert facts["entry_section"] is None

    def test_a_zerofill_section_cannot_claim_the_entry(self, tmp_path: Path) -> None:
        # A zerofill section records offset 0 and owns no file bytes; its
        # size span must not swallow a small entryoff.
        seg = _lc_segment64_with_named_sections(0x100000000, 0, 0x1000, [("__bss", 0, 0x10000)])
        cmds = seg + _lc_main(0x800)
        data = _macho64_full(2, 0, cmds, ncmds=2)
        facts = describe_native(_write(tmp_path, "bss.macho", data))["native"]
        assert facts["entry_section"] is None

    def test_the_committed_macho_fixture_enters_via_text(self) -> None:
        fixture = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        facts = describe_native(fixture)["native"]
        assert facts["entry_section"] == "__text"


def _lc_function_starts(dataoff: int, datasize: int) -> bytes:
    # linkedit_data_command: LC_FUNCTION_STARTS names where the ULEB128 run lives.
    cmd = bytearray(16)
    cmd[0:4] = (0x26).to_bytes(4, "little")
    cmd[4:8] = (16).to_bytes(4, "little")
    cmd[8:12] = dataoff.to_bytes(4, "little")
    cmd[12:16] = datasize.to_bytes(4, "little")
    return bytes(cmd)


def _elf64_with_eh_frame_hdr(header: bytes) -> bytes:
    # A single PT_GNU_EH_FRAME mapping the .eh_frame_hdr bytes.
    ph_off = 64
    blob_off = ph_off + 56
    program = _phdr64(0x6474E550, blob_off, len(header))
    return _ehdr64(2, phoff=ph_off, phnum=1, shoff=0, shnum=0) + program + header


def _eh_frame_hdr(
    fde_count: int,
    *,
    version: int = 1,
    ptr_enc: int = 0x1B,
    count_enc: int = 0x03,
    count_size: int = 4,
) -> bytes:
    # The GNU shape: version, ptr/count/table encodings, a 4-byte pcrel
    # sdata4 eh_frame_ptr, then the count in the given width.
    return (
        bytes([version, ptr_enc, count_enc, 0x3B])
        + (0x1000).to_bytes(4, "little")
        + fde_count.to_bytes(count_size, "little")
    )


class TestFunctionCensus:
    """The function census that survives stripping, on its native members.

    strip removes symbol tables but not what the runtime itself needs: ELF
    keeps the .eh_frame_hdr the unwinder binary-searches (fde_count, one FDE
    per function), Mach-O keeps LC_FUNCTION_STARTS (dyld and the crash
    reporter read it). Both counts are the honest size of the analysis
    surface for a stripped image -- the family PE joins through its .pdata
    table. Gated against llvm-dwarfdump's FDE walk and llvm-objdump's
    --function-starts decode.
    """

    def test_a_gcc_shaped_eh_frame_hdr_reads_its_fde_count(self, tmp_path: Path) -> None:
        data = _elf64_with_eh_frame_hdr(_eh_frame_hdr(7))
        facts = describe_native(_write(tmp_path, "plain.elf", data))["native"]
        assert facts["eh_frame_functions"] == 7

    def test_an_absptr_count_is_read_pointer_sized(self, tmp_path: Path) -> None:
        # DW_EH_PE_absptr (0x00) sizes the count by the ELF class: 8 bytes here.
        data = _elf64_with_eh_frame_hdr(
            _eh_frame_hdr(3, count_enc=0x00, count_size=8)
        )
        facts = describe_native(_write(tmp_path, "absptr.elf", data))["native"]
        assert facts["eh_frame_functions"] == 3

    def test_an_omitted_count_fails_closed(self, tmp_path: Path) -> None:
        # DW_EH_PE_omit for the count: the header declares no count at all,
        # and inventing one from the table would be a guess.
        data = _elf64_with_eh_frame_hdr(_eh_frame_hdr(0, count_enc=0xFF, count_size=0))
        facts = describe_native(_write(tmp_path, "omit.elf", data))["native"]
        assert "eh_frame_functions" not in facts

    def test_an_unknown_header_version_fails_closed(self, tmp_path: Path) -> None:
        data = _elf64_with_eh_frame_hdr(_eh_frame_hdr(7, version=2))
        facts = describe_native(_write(tmp_path, "v2.elf", data))["native"]
        assert "eh_frame_functions" not in facts

    def test_an_elf_without_the_segment_reports_nothing(self, tmp_path: Path) -> None:
        data = _elf64_dynamic_pie()
        facts = describe_native(_write(tmp_path, "noeh.elf", data))["native"]
        assert "eh_frame_functions" not in facts

    def test_a_macho_function_starts_run_counts_its_entries(self, tmp_path: Path) -> None:
        # 0x1000, +0x40, +0x30, terminator: three functions.
        blob = b"\x80\x20\x40\x30\x00"
        data = _macho64_full(2, 0, _lc_function_starts(32 + 16, len(blob)), ncmds=1) + blob
        facts = describe_native(_write(tmp_path, "fs.macho", data))["native"]
        assert facts["function_starts"] == 3

    def test_an_all_zero_run_counts_no_functions(self, tmp_path: Path) -> None:
        # A present table with only the terminator: zero functions is a real
        # answer (linkers pad the blob with zeros).
        blob = b"\x00\x00\x00\x00"
        data = _macho64_full(2, 0, _lc_function_starts(32 + 16, len(blob)), ncmds=1) + blob
        facts = describe_native(_write(tmp_path, "empty.macho", data))["native"]
        assert facts["function_starts"] == 0

    def test_a_truncated_uleb_fails_closed(self, tmp_path: Path) -> None:
        # The blob ends mid-value (continuation bit set on its last byte):
        # the count cannot be trusted, so no fact rather than a guess.
        blob = b"\x80\x20\x40\x80"
        data = _macho64_full(2, 0, _lc_function_starts(32 + 16, len(blob)), ncmds=1) + blob
        facts = describe_native(_write(tmp_path, "cut.macho", data))["native"]
        assert "function_starts" not in facts

    def test_a_table_past_the_end_of_the_file_fails_closed(self, tmp_path: Path) -> None:
        data = _macho64_full(2, 0, _lc_function_starts(32 + 16, 4096), ncmds=1) + b"\x10\x00"
        facts = describe_native(_write(tmp_path, "liar.macho", data))["native"]
        assert "function_starts" not in facts

    def test_the_committed_macho_fixture_carries_no_table(self) -> None:
        # The hand-built fixture ships no LC_FUNCTION_STARTS: the fact must
        # stay absent, not read 0 off some other command.
        fixture = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        facts = describe_native(fixture)["native"]
        assert "function_starts" not in facts

    def test_a_session_over_an_elf_carries_the_count(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "app.elf", _elf64_with_eh_frame_hdr(_eh_frame_hdr(5)))
        session = SessionRegistry().create(str(path))
        assert session.metadata["native"]["eh_frame_functions"] == 5
