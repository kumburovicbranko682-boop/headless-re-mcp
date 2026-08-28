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


def _lc_load_dylib(name: str) -> bytes:
    raw = name.encode() + b"\x00"
    total = (24 + len(raw) + 3) & ~3  # dylib_command struct is 24 bytes, then the name
    cmd = bytearray(total)
    cmd[0:4] = (0x0C).to_bytes(4, "little")  # LC_LOAD_DYLIB
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


def _lc_build_version(platform: int, minos: int, sdk: int) -> bytes:
    # build_version_command with no trailing build_tool_version entries.
    cmd = bytearray(24)
    cmd[0:4] = (0x32).to_bytes(4, "little")  # LC_BUILD_VERSION
    cmd[4:8] = (24).to_bytes(4, "little")
    cmd[8:12] = platform.to_bytes(4, "little")
    cmd[12:16] = minos.to_bytes(4, "little")
    cmd[16:20] = sdk.to_bytes(4, "little")
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


def _lc_encryption_info(cryptid: int, cmd: int = 0x2C) -> bytes:
    # LC_ENCRYPTION_INFO(_64): cryptoff/cryptsize then cryptid (+ pad for _64).
    return (
        cmd.to_bytes(4, "little")
        + (24).to_bytes(4, "little")
        + (0x1000).to_bytes(4, "little")
        + (0x1000).to_bytes(4, "little")
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


def _lc_segment64(vmaddr: int, fileoff: int, filesize: int) -> bytes:
    cmd = bytearray(72)
    cmd[0:4] = (0x19).to_bytes(4, "little")  # LC_SEGMENT_64
    cmd[4:8] = (72).to_bytes(4, "little")
    cmd[8:24] = b"__TEXT".ljust(16, b"\x00")
    cmd[24:32] = vmaddr.to_bytes(8, "little")
    cmd[32:40] = (0x1000).to_bytes(8, "little")  # vmsize
    cmd[40:48] = fileoff.to_bytes(8, "little")
    cmd[48:56] = filesize.to_bytes(8, "little")
    return bytes(cmd)


def _lc_segment32(vmaddr: int, fileoff: int, filesize: int) -> bytes:
    cmd = bytearray(56)
    cmd[0:4] = (0x01).to_bytes(4, "little")  # LC_SEGMENT
    cmd[4:8] = (56).to_bytes(4, "little")
    cmd[8:24] = b"__TEXT".ljust(16, b"\x00")
    cmd[24:28] = vmaddr.to_bytes(4, "little")
    cmd[28:32] = (0x1000).to_bytes(4, "little")  # vmsize
    cmd[32:36] = fileoff.to_bytes(4, "little")
    cmd[36:40] = filesize.to_bytes(4, "little")
    return bytes(cmd)


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


def _elf64_relro(*, bind_now_tag: bool = False, flags: int = 0, flags_1: int = 0) -> bytes:
    """A dynamic ELF carrying PT_GNU_RELRO plus a controllable dynamic section.

    RELRO is partial with only the segment present; it upgrades to full when the
    dynamic section forces eager binding -- via a DT_BIND_NOW tag, DF_BIND_NOW in
    DT_FLAGS, or DF_1_NOW in DT_FLAGS_1 -- so each of the three markers is
    exercised through the same builder.
    """
    entries: list[tuple[int, int]] = []
    if bind_now_tag:
        entries.append((24, 0))  # DT_BIND_NOW
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
    assert facts["entry"] == 0x100000358
    # Its build posture, cross-checked against radare2 by the r2 gate: NX on,
    # stack-protector imports present, no FairPlay encryption.
    assert facts["nx"] is True
    assert facts["canary"] is True
    assert facts["encrypted"] is False
    # The one symbol the fixture defines externally (_main); the stack_chk pair
    # are undefined imports on the other side of the split. The toolchain gate
    # cross-checks both sets against llvm-nm.
    assert facts["exported_symbols"] == ["_main"]
    assert facts["imported_symbols"] == ["___stack_chk_fail", "___stack_chk_guard"]
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


def test_java_class_is_not_mistaken_for_a_universal_binary(tmp_path: Path) -> None:
    # Shares 0xCAFEBABE but the "slice count" is a Java version >= 45.
    path = _write(tmp_path, "T.class", _java_class())
    assert classify_target(str(path)) is TargetKind.PE
    assert describe_native(path) == {}


def test_non_native_returns_empty(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", b"MZ\x90\x00 not really but not native either")
    assert describe_native(path) == {}


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
