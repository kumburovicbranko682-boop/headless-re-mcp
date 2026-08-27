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


def _elf64_static_with_symtab() -> bytes:
    ph_off = 64
    sh_off = ph_off + 56  # one program header
    program = _phdr64(1)  # PT_LOAD, no dynamic/interp -> static
    sections = _shdr64(0) + _shdr64(2)  # SHT_NULL + SHT_SYMTAB -> not stripped
    ehdr = _ehdr64(2, phoff=ph_off, phnum=1, shoff=sh_off, shnum=2)  # ET_EXEC
    return ehdr + program + sections


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


def _elf64_dynamic_with_strtab(strtab: bytes) -> bytes:
    """A dynamic ELF whose DT_STRTAB points at ``strtab``.

    A PT_LOAD with vaddr == offset == 0 makes DT_STRTAB's virtual address map
    straight to its file offset, the same trick the DT_NEEDED builder uses, so
    the reader resolves the string table exactly as it does on a real image.
    """
    dyn = b"".join(
        tag.to_bytes(8, "little") + val.to_bytes(8, "little")
        for tag, val in (
            (5, 176),  # DT_STRTAB (vaddr == file offset of the string table)
            (10, len(strtab)),  # DT_STRSZ
            (0, 0),  # DT_NULL
        )
    )
    ph_off = 64
    strtab_off = ph_off + 56 * 2  # == 176, matching DT_STRTAB above
    dyn_off = strtab_off + len(strtab)
    program = _phdr64(1, p_offset=0, p_filesz=0x10000, p_vaddr=0) + _phdr64(2, dyn_off, len(dyn))
    ehdr = _ehdr64(3, phoff=ph_off, phnum=2, shoff=0, shnum=0)  # ET_DYN
    return ehdr + program + strtab + dyn


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


def test_soname_and_build_id_from_a_shared_object(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_shared_with_soname_and_build_id())
    facts = describe_native(path)["native"]
    # DT_SONAME is the provider-side pair to DT_NEEDED, present only on a library.
    assert facts["soname"] == "libmylib.so.1"
    assert facts["needed"] == ["libc.so.6"]
    # The GNU build-id from the PT_NOTE record, hex-encoded.
    assert facts["build_id"] == "deadbeef01020304"


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


def test_committed_macho_fixture_entry_matches_its_layout() -> None:
    # The committed fixture's LC_MAIN points at its code blob inside __TEXT
    # (vmaddr 0x100000000, fileoff 0), so the mapped entry is a known constant
    # the r2/Ghidra gates also cross-check against real tool output.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")
    facts = describe_native(fixture)["native"]
    assert facts["entry"] == 0x1000001D0


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
