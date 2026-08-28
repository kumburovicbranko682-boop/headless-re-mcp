"""Cross-validate the native PE hardening posture against pefile and mcs.

A session over a PE now reads its build posture off the optional header -- the
pair to the ELF nx/relro/canary/pie and Mach-O nx/pie facts: the subsystem
(gui/console/driver/EFI), the DllCharacteristics loader-mitigation bits
(DYNAMICBASE -> aslr, NX_COMPAT -> nx, GUARD_CF -> cfg, high-entropy VA, forced
integrity, AppContainer, no-SEH), the declared minimum Windows (the OS and
subsystem version pairs -- the PE minimum-runtime fact, the pair to Mach-O's
min_os), and the entry VA rebased to the preferred image base. The field
offsets, the PE32/PE32+ ImageBase switch and the bit
decode are all ours, so pefile referees them: it locates the optional header
independently and decodes the same fields through its own constant tables
(DLL_CHARACTERISTICS, SUBSYSTEM_TYPE), which this compares against the reader's
facts bit for bit. A second case compiles a real PE with Mono's mcs so at least
one gated binary comes from a producer neither builder controls.

The load-config gate covers the mitigations the DllCharacteristics bits don't
carry: ``gs`` -- the /GS stack cookie, the PE canary, the pair to the
ELF/Mach-O canary facts, read off the load config's SecurityCookie VA -- and,
for PE32 only, ``safe_seh`` off the SEHandlerTable/Count pair. The struct
layouts diverge between PE32 and PE32+ (most fields widen to pointers), and
the offsets are ours, so pefile referees them: it parses
IMAGE_LOAD_CONFIG_DIRECTORY through its own format strings and exposes the
same fields by name.

pefile ships in the project's ``pe`` extra; mcs comes from mono-mcs in CI. skip
!= pass: each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

# Reader fact name -> the pefile flag name whose bit it must mirror.
_MITIGATION_TO_PEFILE = {
    "high_entropy_va": "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
    "aslr": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    "force_integrity": "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
    "nx": "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    "no_seh": "IMAGE_DLLCHARACTERISTICS_NO_SEH",
    "appcontainer": "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
    "cfg": "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
}
# pefile subsystem constant name -> the reader's subsystem fact value.
_SUBSYSTEM_BY_PEFILE = {
    "IMAGE_SUBSYSTEM_UNKNOWN": "unknown",
    "IMAGE_SUBSYSTEM_NATIVE": "native",
    "IMAGE_SUBSYSTEM_WINDOWS_GUI": "gui",
    "IMAGE_SUBSYSTEM_WINDOWS_CUI": "console",
    "IMAGE_SUBSYSTEM_EFI_APPLICATION": "efi_application",
}
# pefile machine constant name -> the reader's arch fact value: pefile decodes
# the COFF Machine field through its own MACHINE_TYPE table, so the mapping
# below is the only shared vocabulary between referee and reader.
_ARCH_BY_PEFILE = {
    "IMAGE_FILE_MACHINE_I386": "x86",
    "IMAGE_FILE_MACHINE_AMD64": "x86-64",
    "IMAGE_FILE_MACHINE_ARM64": "arm64",
    "IMAGE_FILE_MACHINE_ARM": "arm",
    "IMAGE_FILE_MACHINE_ARMNT": "arm",
}


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _pe_with_posture(
    *,
    magic: int,
    subsystem: int,
    dllchar: int,
    entry_rva: int,
    image_base: int,
    machine: int | None = None,
    os_version: tuple[int, int] = (6, 0),
    subsys_version: tuple[int, int] = (6, 0),
) -> bytes:
    """A minimal one-section PE whose optional header carries the given posture.

    Built here independently of the reader's own test builder so the two
    implementations cannot share a blind spot; the section exists so a nonzero
    AddressOfEntryPoint points at real image bytes, the shape pefile expects.
    """
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    if machine is None:
        machine = 0x8664 if magic == 0x20B else 0x14C
    opt_size = 0xF0 if magic == 0x20B else 0xE0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<I", opt, 16, entry_rva)
    if magic == 0x20B:
        struct.pack_into("<Q", opt, 24, image_base)
    else:
        struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<HH", opt, 40, *os_version)
    struct.pack_into("<HH", opt, 48, *subsys_version)
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<H", opt, 68, subsystem)
    struct.pack_into("<H", opt, 70, dllchar)
    struct.pack_into("<I", opt, 108 if magic == 0x20B else 92, 16)  # NumberOfRvaAndSizes

    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders

    sect = bytearray(40)
    sect[0:5] = b".text"
    struct.pack_into("<I", sect, 8, 0x200)  # VirtualSize
    struct.pack_into("<I", sect, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", sect, 16, 0x200)  # SizeOfRawData
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x60000020)  # code | execute | read

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    out += b"\xc3" + b"\x00" * 0x1FF  # a ret and padding as the section body
    return bytes(out)


def _pefile_posture(pefile_mod: Any, path: Path) -> dict[str, Any]:
    """The posture facts as pefile reads them, through its own constant tables."""
    pe = pefile_mod.PE(str(path))
    header = pe.OPTIONAL_HEADER
    subsystem_name = pefile_mod.SUBSYSTEM_TYPE.get(header.Subsystem, "")
    machine_name = pefile_mod.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "")
    posture: dict[str, Any] = {
        "subsystem": _SUBSYSTEM_BY_PEFILE.get(
            subsystem_name, f"subsystem_{header.Subsystem}"
        ),
        # The CPU identity off the COFF Machine field and the pointer width
        # off the optional-header magic -- pefile classifies both itself
        # (MACHINE_TYPE, PE_TYPE), independently of the reader's tables.
        "arch": _ARCH_BY_PEFILE.get(
            machine_name, f"machine_0x{pe.FILE_HEADER.Machine:04x}"
        ),
        "bits": 64 if pe.PE_TYPE == pefile_mod.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32,
    }
    for fact, flag in _MITIGATION_TO_PEFILE.items():
        posture[fact] = bool(
            header.DllCharacteristics & pefile_mod.DLL_CHARACTERISTICS[flag]
        )
    # The declared minimum Windows -- the pair to Mach-O's min_os, rendered
    # dotted from the same u16 pairs pefile exposes as named fields.
    posture["os_version"] = (
        f"{header.MajorOperatingSystemVersion}.{header.MinorOperatingSystemVersion}"
    )
    posture["subsystem_version"] = (
        f"{header.MajorSubsystemVersion}.{header.MinorSubsystemVersion}"
    )
    if header.AddressOfEntryPoint:
        posture["entry"] = header.ImageBase + header.AddressOfEntryPoint
    return posture


def _session_posture(path: Path) -> dict[str, Any]:
    """The reader's posture facts, extracted from a session's PE metadata."""
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        pe = created.data["session"]["metadata"]["pe"]
        keys = {
            "arch",
            "bits",
            "subsystem",
            "os_version",
            "subsystem_version",
            "entry",
            *_MITIGATION_TO_PEFILE,
        }
        return {key: value for key, value in pe.items() if key in keys}
    finally:
        service.close_all()


_HARDENED = 0x0020 | 0x0040 | 0x0100 | 0x4000  # high-entropy, aslr, nx, cfg
_SANDBOXED = 0x0080 | 0x0400 | 0x1000  # force-integrity, no-seh, appcontainer


@pytest.mark.integration
@pytest.mark.parametrize(
    ("magic", "subsystem", "dllchar", "entry_rva", "image_base"),
    [
        # A modern MSVC-shaped GUI exe: 64-bit, fully mitigation-opted.
        (0x20B, 2, _HARDENED, 0x1000, 0x1_4000_0000),
        # A legacy 32-bit console exe: no mitigations at all.
        (0x10B, 3, 0, 0x1000, 0x40_0000),
        # An AppContainer store DLL with no declared entry point.
        (0x20B, 2, _SANDBOXED, 0, 0x1_8000_0000),
    ],
    ids=["pe32+-hardened-gui", "pe32-legacy-console", "pe32+-appcontainer-noentry"],
)
def test_posture_agrees_with_pefile(
    tmp_path: Path,
    magic: int,
    subsystem: int,
    dllchar: int,
    entry_rva: int,
    image_base: int,
) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE hardening gate not run (skip != pass)")

    binary = tmp_path / f"posture_{magic:x}_{dllchar:04x}.exe"
    binary.write_bytes(
        _pe_with_posture(
            magic=magic,
            subsystem=subsystem,
            dllchar=dllchar,
            entry_rva=entry_rva,
            image_base=image_base,
        )
    )

    # Independent ground truth: pefile locates the optional header itself and
    # decodes the same fields through its own constant tables. The fields must
    # be what we planted, so pefile is a genuine second opinion.
    expected = _pefile_posture(pefile_mod, binary)
    pe = pefile_mod.PE(str(binary))
    assert pe.OPTIONAL_HEADER.Subsystem == subsystem
    assert pe.OPTIONAL_HEADER.DllCharacteristics == dllchar
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == entry_rva
    assert expected["os_version"] == "6.0"  # the builder's planted minimum

    # Bit for bit: subsystem name, all seven mitigation facts, the declared
    # minimum Windows pairs, and the entry VA (present and rebased
    # identically, or absent on both sides).
    assert _session_posture(binary) == expected


@pytest.mark.integration
def test_an_arm64_machine_field_agrees_with_pefile(tmp_path: Path) -> None:
    # The one mainstream machine value the x86-centric builders above never
    # produce: Windows-on-ARM. pefile names it through MACHINE_TYPE; the
    # reader must land on the same "arm64" -- and stay 64-bit off the magic.
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE hardening gate not run (skip != pass)")
    binary = tmp_path / "woa.exe"
    binary.write_bytes(
        _pe_with_posture(
            magic=0x20B,
            subsystem=2,
            dllchar=_HARDENED,
            entry_rva=0x1000,
            image_base=0x1_4000_0000,
            machine=0xAA64,
        )
    )
    expected = _pefile_posture(pefile_mod, binary)
    assert expected["arch"] == "arm64"  # the referee really saw ARM64
    assert expected["bits"] == 64
    assert _session_posture(binary) == expected


@pytest.mark.integration
def test_arch_and_bits_of_the_committed_fixtures_agree_with_pefile() -> None:
    # Real linker output on both sides of the width split: the MinGW-built
    # UPX pair (x86 and x64, packed and unpacked) plus the managed fixture.
    # pefile classifies each through FILE_HEADER.Machine and PE_TYPE; the
    # reader's arch/bits must match binary for binary.
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE hardening gate not run (skip != pass)")
    fixtures = Path(__file__).resolve().parents[2] / "fixtures"
    binaries = sorted((fixtures / "upx").glob("*.exe")) + [
        fixtures / "dotnet" / "minimal_assembly.exe"
    ]
    binaries = [path for path in binaries if path.is_file()]
    if not binaries:
        pytest.skip("no committed PE fixtures found")
    for binary in binaries:
        expected = _pefile_posture(pefile_mod, binary)
        session = _session_posture(binary)
        assert session["arch"] == expected["arch"], binary.name
        assert session["bits"] == expected["bits"], binary.name


@pytest.mark.integration
def test_posture_of_an_mcs_compiled_pe_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE hardening gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    # A real compiler's PE, so at least one gated binary has posture fields
    # neither this gate's builder nor the reader's test builder wrote.
    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    expected = _pefile_posture(pefile_mod, binary)
    # Mono's linker has emitted DYNAMICBASE and NX_COMPAT console exes for
    # years; assert the referee sees a real posture so the comparison below
    # cannot pass vacuously on an all-False parse. The declared minimum
    # Windows must be a real pair too (the loader refuses a zero subsystem
    # version, so no working compiler emits one).
    assert expected["subsystem"] == "console"
    assert expected["aslr"] is True
    assert expected["nx"] is True
    assert "entry" in expected
    assert expected["subsystem_version"] != "0.0"

    assert _session_posture(binary) == expected

    # The same compiler PE through the load-config gate: whatever Mono's
    # linker did or did not emit, the reader and pefile must agree on it.
    assert _session_load_config(binary) == _pefile_load_config(pefile_mod, binary)


def _pe_with_load_config(
    *,
    magic: int,
    cookie_va: int,
    seh_table: int = 0,
    seh_count: int = 0,
    with_config: bool = True,
) -> bytes:
    """A one-section PE carrying a load-config directory, built independently.

    Unlike the reader's own test builder this one parks the struct at +0x40
    into the section (not at its start) and always writes the full winnt.h
    span through the SEH fields, so a reader that only works for structs at a
    section boundary would fail here. ``with_config=False`` leaves directory
    10 zeroed -- the no-mitigation baseline.
    """
    image_base = 0x1_4000_0000 if magic == 0x20B else 0x40_0000
    sect_rva = 0x2000
    struct_off = 0x40
    span = 112 if magic == 0x20B else 72
    sec = bytearray(0x400)
    struct.pack_into("<I", sec, struct_off, span)
    if magic == 0x20B:
        struct.pack_into("<Q", sec, struct_off + 88, cookie_va)
    else:
        struct.pack_into("<I", sec, struct_off + 60, cookie_va)
        struct.pack_into("<II", sec, struct_off + 64, seh_table, seh_count)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    machine = 0x8664 if magic == 0x20B else 0x14C
    opt_size = 0xF0 if magic == 0x20B else 0xE0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    if magic == 0x20B:
        struct.pack_into("<Q", opt, 24, image_base)
    else:
        struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, sect_rva + len(sec))  # SizeOfImage
    dir_count_off = 108 if magic == 0x20B else 92
    struct.pack_into("<I", opt, dir_count_off, 16)
    if with_config:
        struct.pack_into(
            "<II", opt, dir_count_off + 4 + 10 * 8, sect_rva + struct_off, span
        )

    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders

    sect = bytearray(40)
    sect[0:6] = b".rdata"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, len(sec))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)  # initialized data | read

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


def _pefile_load_config(pefile_mod: Any, path: Path) -> dict[str, Any]:
    """gs/safe_seh as pefile reads them off its own load-config parse."""
    pe = pefile_mod.PE(str(path))
    is_pe32 = pe.OPTIONAL_HEADER.Magic == 0x10B
    facts: dict[str, Any] = {"gs": False}
    if is_pe32:
        facts["safe_seh"] = False
    config = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if config is None:
        return facts
    facts["gs"] = bool(getattr(config.struct, "SecurityCookie", 0) or 0)
    if is_pe32:
        table = getattr(config.struct, "SEHandlerTable", 0) or 0
        count = getattr(config.struct, "SEHandlerCount", 0) or 0
        facts["safe_seh"] = bool(table and count)
    return facts


def _session_load_config(path: Path) -> dict[str, Any]:
    """The reader's gs/safe_seh facts, extracted from a session's PE metadata."""
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        pe = created.data["session"]["metadata"]["pe"]
        return {key: pe[key] for key in ("gs", "safe_seh") if key in pe}
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize(
    ("magic", "cookie_va", "seh_table", "seh_count", "with_config"),
    [
        # A /GS-built 64-bit image: cookie VA set, no SEH fields to speak of.
        (0x20B, 0x1_4000_3000, 0, 0, True),
        # A fully mitigated 32-bit image: /GS cookie plus a /SAFESEH table.
        (0x10B, 0x40_3000, 0x40_3100, 4, True),
        # A load config shipped for other reasons: cookie zero, no SafeSEH.
        (0x20B, 0, 0, 0, True),
        # No load config at all -- the no-mitigation baseline.
        (0x10B, 0, 0, 0, False),
    ],
    ids=["pe32+-gs", "pe32-gs-safeseh", "pe32+-config-no-gs", "pe32-no-config"],
)
def test_load_config_mitigations_agree_with_pefile(
    tmp_path: Path,
    magic: int,
    cookie_va: int,
    seh_table: int,
    seh_count: int,
    with_config: bool,
) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE load-config gate not run (skip != pass)")

    binary = tmp_path / f"loadcfg_{magic:x}_{cookie_va:x}.exe"
    binary.write_bytes(
        _pe_with_load_config(
            magic=magic,
            cookie_va=cookie_va,
            seh_table=seh_table,
            seh_count=seh_count,
            with_config=with_config,
        )
    )

    # Referee sanity: pefile must actually see the planted struct, so the
    # comparison below cannot pass vacuously on a failed parse.
    expected = _pefile_load_config(pefile_mod, binary)
    if with_config:
        pe = pefile_mod.PE(str(binary))
        assert pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie == cookie_va
    assert expected["gs"] is bool(cookie_va)
    if magic == 0x10B:
        assert expected["safe_seh"] is bool(seh_table and seh_count)

    # Field for field: the /GS verdict on both widths, and the SafeSEH verdict
    # wherever the 32-bit layout defines it (PE32+ must omit the key).
    assert _session_load_config(binary) == expected
