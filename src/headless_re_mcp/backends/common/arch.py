"""Name a binary's CPU architecture from its header, without running a tool.

The portable static backends -- radare2 and Ghidra -- disassemble whatever
format they are handed (PE, ELF, Mach-O), yet their results said nothing about
*which* architecture that was. A caller reading x64 disassembly as x86, or arm64
as x64, reads it wrong, and for a non-PE target the field was simply absent.

``binary_architecture`` answers that from a short prefix read -- the same field
each format fixes in its first bytes -- so it costs a few bytes off disk rather
than slurping a large target or spawning the tool a second time. Only the four
CPUs the :class:`Architecture` model can name are returned; every other machine
(MIPS, RISC-V, PPC, ...), a fat/universal Mach-O (several slices, no single
architecture), and an unrecognised file yield ``None`` so the caller omits the
field rather than guessing.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.models import Architecture

# PE optional-header magic can sit past a long DOS stub; this window reaches it
# for any real file without reading the whole target.
_PE_WINDOW = 64 * 1024


def pe_architecture(binary: Path) -> Architecture | None:
    """x86/x64 from a PE optional-header magic, or None if the file is not PE."""
    try:
        with binary.open("rb") as stream:
            data = stream.read(_PE_WINDOW)
    except OSError:
        return None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    optional_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    optional = data[pe_offset + 24 : pe_offset + 24 + optional_size]
    if len(optional) < 2:
        return None
    magic = int.from_bytes(optional[0:2], "little")
    if magic == 0x10B:  # PE32
        return Architecture.X86
    if magic == 0x20B:  # PE32+
        return Architecture.X64
    return None


def elf_architecture(binary: Path) -> Architecture | None:
    """x86/x64/arm/arm64 from an ELF ``e_machine`` field, or None if not ELF.

    ``e_machine`` is a two-byte field at offset 18, written in the byte order
    ``e_ident[EI_DATA]`` (offset 5) declares. ``EM_386`` -> x86, ``EM_X86_64``
    -> x64, ``EM_ARM`` -> arm, ``EM_AARCH64`` -> arm64 (the shape of an Android
    arm64-v8a native library); other machines yield ``None``.
    """
    try:
        with binary.open("rb") as stream:
            head = stream.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    ei_data = head[5]
    if ei_data == 1:
        e_machine = int.from_bytes(head[18:20], "little")
    elif ei_data == 2:
        e_machine = int.from_bytes(head[18:20], "big")
    else:
        return None
    if e_machine == 3:  # EM_386
        return Architecture.X86
    if e_machine == 62:  # EM_X86_64
        return Architecture.X64
    if e_machine == 40:  # EM_ARM
        return Architecture.ARM
    if e_machine == 183:  # EM_AARCH64
        return Architecture.ARM64
    return None


def macho_architecture(binary: Path) -> Architecture | None:
    """x86/x64/arm/arm64 from a thin Mach-O ``cputype``, or None otherwise.

    The magic in the first four bytes fixes word size and byte order; ``cputype``
    is the four bytes after it, read in that order. ``CPU_TYPE_X86`` -> x86,
    ``CPU_TYPE_X86_64`` -> x64, ``CPU_TYPE_ARM`` -> arm, ``CPU_TYPE_ARM64`` ->
    arm64. A fat/universal archive (0xCAFEBABE and friends) has several slices
    with no single architecture, so it -- like any other CPU or a non-Mach-O
    file -- yields ``None``.
    """
    try:
        with binary.open("rb") as stream:
            head = stream.read(8)
    except OSError:
        return None
    if len(head) < 8:
        return None
    magic = head[:4]
    if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        cputype = int.from_bytes(head[4:8], "little")
    elif magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        cputype = int.from_bytes(head[4:8], "big")
    else:
        return None
    if cputype == 0x00000007:  # CPU_TYPE_X86 (i386)
        return Architecture.X86
    if cputype == 0x01000007:  # CPU_TYPE_X86_64
        return Architecture.X64
    if cputype == 0x0000000C:  # CPU_TYPE_ARM
        return Architecture.ARM
    if cputype == 0x0100000C:  # CPU_TYPE_ARM64
        return Architecture.ARM64
    return None


def binary_architecture(binary: Path) -> Architecture | None:
    """Name a binary's architecture from its header: PE, then ELF, then Mach-O.

    Each reader returns ``None`` unless its own magic matches, so the order only
    decides who answers, never a misread. ``None`` means no format recognised
    the file or the format's machine is one the model cannot name.
    """
    return (
        pe_architecture(binary)
        or elf_architecture(binary)
        or macho_architecture(binary)
    )
