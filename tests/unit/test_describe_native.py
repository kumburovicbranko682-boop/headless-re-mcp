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


def _macho_fat(*cputypes: int) -> bytes:
    header = b"\xca\xfe\xba\xbe" + len(cputypes).to_bytes(4, "big")
    for cputype in cputypes:
        header += cputype.to_bytes(4, "big") + b"\x00" * 16
    return header


def _java_class() -> bytes:
    # 0xCAFEBABE then minor=0, major=52 (Java 8), then a constant-pool count.
    return b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (52).to_bytes(2, "big") + b"\x00" * 8


def _phdr64(p_type: int, p_offset: int = 0, p_filesz: int = 0, p_vaddr: int = 0) -> bytes:
    entry = bytearray(56)
    entry[0:4] = p_type.to_bytes(4, "little")
    entry[8:16] = p_offset.to_bytes(8, "little")
    entry[16:24] = p_vaddr.to_bytes(8, "little")
    entry[32:40] = p_filesz.to_bytes(8, "little")
    return bytes(entry)


def _shdr64(sh_type: int) -> bytes:
    entry = bytearray(64)
    entry[4:8] = sh_type.to_bytes(4, "little")
    return bytes(entry)


def _ehdr64(e_type: int, *, phoff: int, phnum: int, shoff: int, shnum: int) -> bytes:
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1  # 64-bit, little-endian, version 1
    ehdr[16:18] = e_type.to_bytes(2, "little")
    ehdr[18:20] = (62).to_bytes(2, "little")  # x86-64
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


def test_dynamic_needed_libraries_from_the_dynamic_string_table(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.bin", _elf64_dynamic_with_needed())
    facts = describe_native(path)["native"]
    assert facts["linking"] == "dynamic"
    # The ELF analogue of Mach-O's dylibs: DT_NEEDED resolved through DT_STRTAB.
    assert facts["needed"] == ["libc.so.6", "libm.so.6"]


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
