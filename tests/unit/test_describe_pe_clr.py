"""describe_pe_clr: tool-free .NET identity facts for a PE (no dotnet.inspect).

A managed assembly is a PE, so it classifies as a PE target and used to carry
only its architecture. describe_pe_clr adds the first fork of a Windows-binary
triage -- is this native or managed, and if managed, which runtime and metadata
version -- by reading just the PE/CLR headers, no external tool and no second
hash of the file. These cover the committed .NET fixture, a synthetic native PE
(which must stay empty so the PE baseline is unchanged), a non-PE input, and the
facts flowing through session creation.
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.session import (
    SessionRegistry,
    _dotnet_high_entropy_resources,
    _dotnet_resource_payloads,
    _pe_authenticode,
    _pe_capability_surface,
    _pe_debug_fingerprint,
    _pe_hardening_facts,
    _pe_high_entropy_sections,
    _pe_overlay,
    _pe_resource_payloads,
    _pe_rich_header,
    _pe_tls_facts,
    _pe_version_info,
    _pe_wx_sections,
    describe_pe_clr,
)

_DOTNET_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
)
_DOTNET_BUILDER = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "build_minimal_dotnet.py"
)


def _dotnet_with_resources(resources: list[tuple[str, bytes]]) -> bytes:
    """A real minimal assembly whose embedded ManifestResources are ``resources``.

    Reuses the committed fixture's builder so the metadata around the resources
    -- every table the ManifestResource read must step over -- is exactly what
    ships, not a hand-rolled shape the parser might tolerate but the runtime
    would not.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("_dotnet_builder", _DOTNET_BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build(resources=resources)  # type: ignore[no-any-return]


_NESTED_ASSEMBLY = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_clr_hint.exe"
)


def _nested_assembly_bytes() -> bytes:
    """A genuine managed PE to embed, or a PE-shaped stand-in if it is missing."""
    if _NESTED_ASSEMBLY.is_file():
        return _NESTED_ASSEMBLY.read_bytes()
    return b"MZ" + bytes(0x50)


def _native_pe() -> bytes:
    """A minimal PE32 with 16 all-zero data directories: valid, but not managed."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")  # e_lfanew
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    optional[0:2] = (0x10B).to_bytes(2, "little")  # PE32
    optional[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes; all dirs zero
    return bytes(dos) + coff + bytes(optional)


def _cli_header_offset(raw: bytes) -> int:
    """File offset of the COR20 (CLI) header, mapping its RVA through sections."""
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    cli_rva = struct.unpack_from("<I", raw, directories + 14 * 8)[0]
    coff = e_lfanew + 4
    sections = struct.unpack_from("<H", raw, coff + 2)[0]
    table = coff + 20 + struct.unpack_from("<H", raw, coff + 16)[0]
    for index in range(sections):
        base = table + index * 40
        virtual_address = struct.unpack_from("<I", raw, base + 12)[0]
        raw_size, raw_pointer = struct.unpack_from("<II", raw, base + 16)
        if virtual_address <= cli_rva < virtual_address + max(raw_size, 1):
            return raw_pointer + (cli_rva - virtual_address)
    raise AssertionError("could not locate the CLI header in the fixture")


def _fixture_with_corflags(tmp_path: Path, flags: int) -> Path:
    """The committed assembly with its COR20 Flags field rewritten to ``flags``."""
    raw = bytearray(_DOTNET_FIXTURE.read_bytes())
    raw[_cli_header_offset(raw) + 16 : _cli_header_offset(raw) + 20] = struct.pack("<I", flags)
    path = tmp_path / f"corflags_{flags:08x}.exe"
    path.write_bytes(raw)
    return path


def test_reads_the_committed_dotnet_fixture() -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    info = describe_pe_clr(_DOTNET_FIXTURE)["dotnet"]
    assert info["is_dotnet"] is True
    assert info["runtime_version"] == "2.5"
    assert info["metadata_version"] == "v4.0.30319"
    # Row 3: the fixture's MethodDef table is .cctor (the module initializer,
    # row 1), Add (row 2), Run (row 3, the entry point).
    assert info["entry_point_token"] == 0x06000003
    assert info["il_only"] is True
    # The fixture's COR20 Flags is ILONLY only (pedump: "ilonly, 32/64,
    # no-trackdebug, notsigned"); the pedump gate cross-checks this.
    assert info["requires_32bit"] is False
    assert info["prefers_32bit"] is False
    assert info["strong_name_signed"] is False


def test_corflags_bits_are_decoded_from_the_cor20_header(tmp_path: Path) -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    # Each corflags bit must be read independently: rewrite only the Flags field
    # of a real assembly and confirm the one fact it controls flips, nothing else.
    ilonly = 0x00000001
    cases = {
        0x00000002: "requires_32bit",  # COMIMAGE_FLAGS_32BITREQUIRED
        0x00020000: "prefers_32bit",  # COMIMAGE_FLAGS_32BITPREFERRED
        0x00000008: "strong_name_signed",  # COMIMAGE_FLAGS_STRONGNAMESIGNED
    }
    for bit, fact in cases.items():
        info = describe_pe_clr(_fixture_with_corflags(tmp_path, ilonly | bit))["dotnet"]
        assert info[fact] is True, fact
        assert info["il_only"] is True
        for other in cases.values():
            if other != fact:
                assert info[other] is False, f"{fact} leaked into {other}"
    # Flags cleared entirely: every posture bit, il_only included, reads False.
    cleared = describe_pe_clr(_fixture_with_corflags(tmp_path, 0))["dotnet"]
    assert cleared["il_only"] is False
    assert cleared["requires_32bit"] is False
    assert cleared["prefers_32bit"] is False
    assert cleared["strong_name_signed"] is False


def _sign_native_pe(
    *,
    cert_type: int = 0x0002,
    revision: int = 0x0200,
    within: bool = True,
    payload: bytes = b"cert",
) -> bytes:
    """A native PE whose security directory points at an appended WIN_CERTIFICATE.

    The directory's first field is a file offset (not an RVA), so the blob is
    glued to the tail and the entry made to point at it -- exactly how a signed
    PE carries its Authenticode PKCS#7. ``within=False`` makes the declared size
    run past the file, the truncated-signature shape.
    """
    base = bytearray(_native_pe())
    blob = struct.pack("<IHH", 8 + len(payload), revision, cert_type) + payload
    cert_offset = len(base)
    declared = len(blob) + (4096 if not within else 0)
    # Optional header starts at 0x40 + 24; PE32 data directories begin at +96,
    # so the security entry (index 4) is at optional[96 + 4*8 : +8].
    security_entry = 0x40 + 24 + 96 + _PE_SECURITY_DIR * 8
    struct.pack_into("<II", base, security_entry, cert_offset, declared)
    return bytes(base) + blob


_PE_SECURITY_DIR = 4


def test_authenticode_absent_reads_unsigned(tmp_path: Path) -> None:
    # A native PE with an all-zero security directory: a real verdict, not
    # absent metadata -- the common unsigned case.
    path = tmp_path / "unsigned.exe"
    path.write_bytes(_native_pe())
    assert _pe_authenticode(path) == {"signed": False}


def test_authenticode_present_reports_the_certificate_range(tmp_path: Path) -> None:
    path = tmp_path / "signed.exe"
    raw = _sign_native_pe(payload=b"PKCS7-BODY")
    path.write_bytes(raw)
    info = _pe_authenticode(path)
    assert info is not None
    assert info["signed"] is True
    # The blob is at the file tail: offset is where the native PE ended, size
    # its whole WIN_CERTIFICATE length, and it fits the file.
    assert info["offset"] == len(_native_pe())
    assert info["size"] == len(raw) - len(_native_pe())
    assert info["within_file"] is True
    assert info["type"] == "pkcs_signed_data"
    assert info["authenticode"] is True
    assert info["revision"] == "2.0"


def test_a_non_authenticode_certificate_type_is_named_not_claimed(tmp_path: Path) -> None:
    # wCertificateType 0x0001 (x509) is a certificate, but not the Authenticode
    # PKCS#7 shape -- signed stays True, authenticode goes False.
    path = tmp_path / "x509.exe"
    path.write_bytes(_sign_native_pe(cert_type=0x0001))
    info = _pe_authenticode(path)
    assert info is not None
    assert info["signed"] is True
    assert info["type"] == "x509"
    assert info["authenticode"] is False


def test_a_signature_running_past_eof_is_flagged(tmp_path: Path) -> None:
    # A directory whose declared size overruns the file: still reported as
    # signed (the claim is there) but within_file False, and the header fields
    # are not read from a range that is not fully present.
    path = tmp_path / "truncated.exe"
    path.write_bytes(_sign_native_pe(within=False))
    info = _pe_authenticode(path)
    assert info is not None
    assert info["signed"] is True
    assert info["within_file"] is False
    assert "type" not in info


def test_authenticode_is_none_for_a_non_pe(tmp_path: Path) -> None:
    path = tmp_path / "notpe.bin"
    path.write_bytes(b"not a PE")
    assert _pe_authenticode(path) is None


class TestPeOverlay:
    """_pe_overlay finds appended data and splits off the signature's share.

    A PE ends at its furthest raw section end; bytes past that were glued on.
    The Authenticode certificate is legitimately appended, so the overlay is
    reported split: certificate_size is the signature's part, extra_size the
    unexplained remainder a dropper would occupy. extra_size 0 (with a cert) is
    a normal signed image; extra_size above 0 is the triage flag.
    """

    def test_a_bare_pe_has_no_overlay(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_overlay(path) is None

    def test_appended_junk_reads_as_unexplained_overlay(self, tmp_path: Path) -> None:
        base = _native_pe()
        path = tmp_path / "dropped.exe"
        path.write_bytes(base + b"SELF-EXTRACT" * 4)
        info = _pe_overlay(path)
        assert info is not None
        assert info["offset"] == len(base)
        assert info["size"] == len("SELF-EXTRACT") * 4
        assert info["certificate_size"] == 0
        assert info["extra_size"] == info["size"]

    def test_a_signed_pe_overlay_is_all_certificate(self, tmp_path: Path) -> None:
        raw = _sign_native_pe(payload=b"PKCS7-BODY")
        path = tmp_path / "signed.exe"
        path.write_bytes(raw)
        info = _pe_overlay(path)
        assert info is not None
        # Every trailing byte is the WIN_CERTIFICATE: nothing unexplained.
        assert info["offset"] == len(_native_pe())
        assert info["certificate_size"] == info["size"]
        assert info["extra_size"] == 0

    def test_a_signed_pe_with_a_stowaway_shows_the_extra_bytes(self, tmp_path: Path) -> None:
        stowaway = b"HIDDEN-PAYLOAD" * 3
        path = tmp_path / "signed-plus.exe"
        path.write_bytes(_sign_native_pe(payload=b"PKCS7-BODY") + stowaway)
        info = _pe_overlay(path)
        assert info is not None
        # The cert share is unchanged; the appended bytes surface as extra.
        assert info["extra_size"] == len(stowaway)
        assert info["certificate_size"] == info["size"] - len(stowaway)

    def test_a_lying_section_size_cannot_invent_an_overlay(self, tmp_path: Path) -> None:
        # Rewrite the (zero) section count is not possible here, so forge a
        # single section whose raw size claims to run past EOF: the image end
        # clamps to the file, so no phantom overlay appears.
        base = bytearray(_native_pe())
        # Turn it into a 1-section PE by bumping NumberOfSections and appending
        # a section header claiming a huge raw size at a tail pointer.
        e = struct.unpack_from("<I", base, 0x3C)[0]
        struct.pack_into("<H", base, e + 4 + 2, 1)  # NumberOfSections = 1
        section = bytearray(40)
        struct.pack_into("<I", section, 16, 0xFFFF)  # SizeOfRawData: lies past EOF
        struct.pack_into("<I", section, 20, len(base) + 40)  # PointerToRawData
        forged = bytes(base) + bytes(section)
        path = tmp_path / "liar.exe"
        path.write_bytes(forged)
        # image end clamps to the file size, so there is no trailing data to
        # report even though the section claims thousands of bytes.
        assert _pe_overlay(path) is None

    def test_non_pe_has_no_overlay(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe at all, just bytes")
        assert _pe_overlay(path) is None


def _pe_with_resources(resources: list[tuple[int, int, bytes]]) -> bytes:
    """A minimal PE32+ whose .rsrc holds a 3-level tree of the given resources.

    Each resource is (type_id, name_id, payload). The tree is Type -> Name ->
    Language, the shape Windows tools and pefile expect, with each data entry's
    OffsetToData an image RVA into the same .rsrc section.
    """
    dirh, ent, datae = 16, 8, 16
    n = len(resources)
    sect_align = 0x1000
    rsrc_rva = sect_align
    type_dir_size = dirh + n * ent
    off = type_dir_size
    name_dir_offs = [off + i * (dirh + ent) for i in range(n)]
    off += n * (dirh + ent)
    lang_dir_offs = [off + i * (dirh + ent) for i in range(n)]
    off += n * (dirh + ent)
    data_entry_offs = [off + i * datae for i in range(n)]
    off += n * datae
    payload_offs: list[int] = []
    for _type_id, _name_id, payload in resources:
        if off % 8:
            off += 8 - (off % 8)
        payload_offs.append(off)
        off += len(payload)
    rsrc_size = off
    buf = bytearray(rsrc_size)
    struct.pack_into("<IIHHHH", buf, 0, 0, 0, 0, 0, 0, n)
    for i, (type_id, name_id, payload) in enumerate(resources):
        name_dir, lang_dir = name_dir_offs[i], lang_dir_offs[i]
        struct.pack_into("<II", buf, dirh + i * ent, type_id, 0x80000000 | name_dir)
        struct.pack_into("<IIHHHH", buf, name_dir, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", buf, name_dir + dirh, name_id, 0x80000000 | lang_dir)
        struct.pack_into("<IIHHHH", buf, lang_dir, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", buf, lang_dir + dirh, 0x0409, data_entry_offs[i])
        struct.pack_into(
            "<IIII", buf, data_entry_offs[i], rsrc_rva + payload_offs[i], len(payload), 0, 0
        )
        buf[payload_offs[i] : payload_offs[i] + len(payload)] = payload
    rsrc = bytes(buf)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x2022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112 + 2 * 8, rsrc_rva, rsrc_size)  # resource dir entry
    raw_off = 0x40 + len(coff) + opt_size
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    sect = bytearray(40)
    sect[0:5] = b".rsrc"
    struct.pack_into("<I", sect, 8, rsrc_size)
    struct.pack_into("<I", sect, 12, rsrc_rva)
    struct.pack_into("<I", sect, 16, len(rsrc))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)
    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    out += rsrc
    return bytes(out)


def _pe_with_imports_exports(
    imports: list[tuple[str, list[object]]],
    exports: list[str],
    *,
    magic: int = 0x20B,
) -> bytes:
    """A minimal PE whose import (index 1) and export (index 0) directories hold
    the given tables, all in one section, the shape pefile and dumpbin parse.

    Each import is ``(dll, functions)`` where a function is a name (by name) or
    an int (by ordinal). ``magic`` selects PE32+ (0x20B) or PE32 (0x10B), which
    sets the thunk width and the ordinal flag the reader must key off.
    """
    sect_rva = 0x1000
    sec = bytearray()

    def emit(data: bytes) -> int:
        off = len(sec)
        sec.extend(data)
        return off

    def align(n: int) -> None:
        while len(sec) % n:
            sec.append(0)

    def rva(off: int) -> int:
        return sect_rva + off

    thunk_fmt = "<Q" if magic == 0x20B else "<I"
    thunk_size = 8 if magic == 0x20B else 4
    ordinal_flag = (1 << 63) if magic == 0x20B else (1 << 31)

    n = len(imports)
    desc_off = emit(b"\x00" * (20 * (n + 1)))  # descriptors + null terminator
    descriptors: list[tuple[int, int]] = []
    for dll, funcs in imports:
        thunks: list[int] = []
        for fn in funcs:
            if isinstance(fn, int):
                thunks.append(ordinal_flag | fn)
                continue
            align(2)  # IMAGE_IMPORT_BY_NAME is WORD-aligned
            hint_name = emit(struct.pack("<H", 0) + fn.encode() + b"\x00")
            thunks.append(rva(hint_name))
        align(thunk_size)
        ilt_off = len(sec)
        for value in thunks:
            emit(struct.pack(thunk_fmt, value))
        emit(struct.pack(thunk_fmt, 0))  # null thunk ends the list
        dll_off = emit(dll.encode() + b"\x00")
        descriptors.append((rva(ilt_off), rva(dll_off)))
    for i, (ilt_rva, dll_rva) in enumerate(descriptors):
        struct.pack_into("<IIIII", sec, desc_off + i * 20, ilt_rva, 0, 0, dll_rva, ilt_rva)
    imp_dir_rva, imp_dir_size = rva(desc_off), 20 * (n + 1)

    exp_dir_rva = exp_dir_size = 0
    if exports:
        name_rvas = [rva(emit(name.encode() + b"\x00")) for name in exports]
        align(4)
        eat_off = len(sec)
        for _ in exports:
            emit(struct.pack("<I", sect_rva))  # a plausible function RVA
        align(4)
        names_off = len(sec)
        for name_rva in name_rvas:
            emit(struct.pack("<I", name_rva))
        ord_off = len(sec)
        for i in range(len(exports)):
            emit(struct.pack("<H", i))
        dll_name = emit(b"self.dll\x00")
        align(4)
        exp_off = len(sec)
        emit(b"\x00" * 40)  # IMAGE_EXPORT_DIRECTORY
        struct.pack_into(
            "<IIHHIIIIIII", sec, exp_off,
            0, 0, 0, 0, rva(dll_name), 1,
            len(exports), len(exports), rva(eat_off), rva(names_off), rva(ord_off),
        )
        exp_dir_rva, exp_dir_size = rva(exp_off), 40

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    machine = 0x8664 if magic == 0x20B else 0x14C
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x2022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    dir_count_off = 108 if magic == 0x20B else 92
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, dir_count_off, 16)  # NumberOfRvaAndSizes
    dir_arr = dir_count_off + 4
    struct.pack_into("<II", opt, dir_arr + 0 * 8, exp_dir_rva, exp_dir_size)
    struct.pack_into("<II", opt, dir_arr + 1 * 8, imp_dir_rva, imp_dir_size)

    raw_off = 0x40 + len(coff) + opt_size
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    rsize = (len(sec) + 0x1FF) & ~0x1FF
    struct.pack_into("<I", opt, 56, 0x2000 + rsize)  # SizeOfImage
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders

    sect = bytearray(40)
    sect[0:6] = b".idata"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, rsize)
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0xC0000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    out += sec
    if len(out) % 0x200:
        out += b"\x00" * (0x200 - (len(out) % 0x200))
    return bytes(out)


# A DOS/PE-header-sized nested image: MZ padded past the sniffer's 0x40 floor.
_NESTED_PE = b"MZ" + b"\x90" * 62 + b"stage-two body"


class TestPeCapabilitySurface:
    """_pe_capability_surface reads the native PE import and export directories.

    The strongest triage signal after arch: which native functions from which
    DLLs the loader must bind (what the binary can actually do), and, for a DLL,
    what it offers back -- the PE pair to an ELF/Mach-O's imported/exported
    symbols. Imports keep import-table order and group by DLL; ordinal-only
    imports read as ``#N``; exports come back name-sorted.
    """

    def test_named_imports_group_under_their_dll(self, tmp_path: Path) -> None:
        path = tmp_path / "imports.exe"
        path.write_bytes(
            _pe_with_imports_exports(
                [
                    ("KERNEL32.dll", ["CreateFileA", "ExitProcess"]),
                    ("USER32.dll", ["MessageBoxW"]),
                ],
                [],
            )
        )
        imports, exports = _pe_capability_surface(path)
        assert exports == []
        assert imports == [
            {"dll": "KERNEL32.dll", "functions": ["CreateFileA", "ExitProcess"]},
            {"dll": "USER32.dll", "functions": ["MessageBoxW"]},
        ]

    def test_ordinal_only_imports_read_as_hash_n(self, tmp_path: Path) -> None:
        path = tmp_path / "ordinal.exe"
        path.write_bytes(_pe_with_imports_exports([("WS2_32.dll", [115, 116])], []))
        imports, _ = _pe_capability_surface(path)
        assert imports == [{"dll": "WS2_32.dll", "functions": ["#115", "#116"]}]

    def test_exports_come_back_name_sorted(self, tmp_path: Path) -> None:
        path = tmp_path / "exports.dll"
        path.write_bytes(_pe_with_imports_exports([], ["ZetaFunc", "AlphaFunc", "MidFunc"]))
        _, exports = _pe_capability_surface(path)
        assert exports == ["AlphaFunc", "MidFunc", "ZetaFunc"]

    def test_a_pe32_import_table_reads_at_the_narrow_thunk_width(self, tmp_path: Path) -> None:
        # PE32 thunks are 4 bytes with the ordinal flag at bit 31; a reader that
        # assumed PE32+ 8-byte thunks would desync immediately.
        path = tmp_path / "x86.exe"
        path.write_bytes(
            _pe_with_imports_exports([("msvcrt.dll", ["printf"])], [], magic=0x10B)
        )
        imports, _ = _pe_capability_surface(path)
        assert imports == [{"dll": "msvcrt.dll", "functions": ["printf"]}]

    def test_a_pe_without_either_directory_reads_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_capability_surface(path) == ([], [])

    def test_a_non_pe_reads_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe at all")
        assert _pe_capability_surface(path) == ([], [])

    def test_the_import_list_is_bounded(self, tmp_path: Path) -> None:
        many = [(f"lib{i:03d}.dll", ["Fn"]) for i in range(300)]
        path = tmp_path / "many.exe"
        path.write_bytes(_pe_with_imports_exports(many, []))
        imports, _ = _pe_capability_surface(path)
        assert len(imports) == 256  # _PE_MAX_IMPORT_DLLS

    def test_session_over_a_pe_carries_the_capability_surface(self, tmp_path: Path) -> None:
        path = tmp_path / "app.exe"
        path.write_bytes(
            _pe_with_imports_exports([("KERNEL32.dll", ["ExitProcess"])], ["Start"])
        )
        session = SessionRegistry().create(str(path))
        assert session.metadata["pe"]["imports"] == [
            {"dll": "KERNEL32.dll", "functions": ["ExitProcess"]}
        ]
        assert session.metadata["pe"]["exports"] == ["Start"]


def _pe_with_posture(
    *,
    subsystem: int = 3,
    dllchar: int = 0,
    entry_rva: int = 0,
    image_base: int = 0x1_4000_0000,
    magic: int = 0x20B,
    os_version: tuple[int, int] = (0, 0),
    subsys_version: tuple[int, int] = (0, 0),
) -> bytes:
    """A minimal PE whose optional header carries the given posture fields.

    Subsystem and DllCharacteristics sit at offsets 68/70 for both PE32 and
    PE32+ (the OS and subsystem version pairs at 40/48 likewise); only
    ImageBase moves (32-bit at 28 vs 64-bit at 24), which is what the entry-VA
    rebase must key off.
    """
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    machine = 0x8664 if magic == 0x20B else 0x14C
    opt_size = 0xF0 if magic == 0x20B else 0xE0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 0, 0, 0, 0, opt_size, 0)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    struct.pack_into("<I", opt, 16, entry_rva)
    if magic == 0x20B:
        struct.pack_into("<Q", opt, 24, image_base)
    else:
        struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<HH", opt, 40, *os_version)
    struct.pack_into("<HH", opt, 48, *subsys_version)
    struct.pack_into("<H", opt, 68, subsystem)
    struct.pack_into("<H", opt, 70, dllchar)
    struct.pack_into("<I", opt, 108 if magic == 0x20B else 92, 16)  # NumberOfRvaAndSizes
    return bytes(dos) + coff + bytes(opt)


class TestPeHardeningFacts:
    """_pe_hardening_facts reads subsystem, mitigations and entry off the header.

    The native PE build posture, the pair to the ELF nx/relro/canary/pie and
    Mach-O nx/pie facts: what kind of program (gui/console/driver/EFI), which
    loader mitigations the image opted into (DYNAMICBASE, NX_COMPAT, GUARD_CF,
    high-entropy VA, forced integrity, AppContainer, no-SEH), and the entry VA
    rebased to the preferred image base.
    """

    _ALL_BITS = 0x0020 | 0x0040 | 0x0080 | 0x0100 | 0x0400 | 0x1000 | 0x4000

    def test_a_fully_hardened_gui_pe_reads_every_mitigation_on(self, tmp_path: Path) -> None:
        path = tmp_path / "hardened.exe"
        path.write_bytes(
            _pe_with_posture(
                subsystem=2,
                dllchar=self._ALL_BITS,
                entry_rva=0x1234,
                os_version=(10, 0),
                subsys_version=(6, 2),
            )
        )
        facts = _pe_hardening_facts(path)
        assert facts == {
            "subsystem": "gui",
            "os_version": "10.0",
            "subsystem_version": "6.2",
            "high_entropy_va": True,
            "aslr": True,
            "force_integrity": True,
            "nx": True,
            "no_seh": True,
            "appcontainer": True,
            "cfg": True,
            "entry": 0x1_4000_1234,
        }

    def test_the_declared_minimum_windows_reads_dotted(self, tmp_path: Path) -> None:
        # The minimum-runtime pair the loader enforces -- the PE min_os,
        # rendered dotted the way Mach-O's min_os and link.exe spell it.
        path = tmp_path / "vista.exe"
        path.write_bytes(_pe_with_posture(os_version=(6, 0), subsys_version=(6, 0)))
        facts = _pe_hardening_facts(path)
        assert facts["os_version"] == "6.0"
        assert facts["subsystem_version"] == "6.0"

    def test_an_unhardened_console_pe_reads_every_mitigation_off(self, tmp_path: Path) -> None:
        path = tmp_path / "soft.exe"
        path.write_bytes(_pe_with_posture(subsystem=3, dllchar=0))
        facts = _pe_hardening_facts(path)
        assert facts["subsystem"] == "console"
        for fact in (
            "high_entropy_va",
            "aslr",
            "force_integrity",
            "nx",
            "no_seh",
            "appcontainer",
            "cfg",
        ):
            assert facts[fact] is False, fact

    def test_each_mitigation_bit_flips_only_its_own_fact(self, tmp_path: Path) -> None:
        bits = {
            0x0020: "high_entropy_va",
            0x0040: "aslr",
            0x0080: "force_integrity",
            0x0100: "nx",
            0x0400: "no_seh",
            0x1000: "appcontainer",
            0x4000: "cfg",
        }
        for bit, fact in bits.items():
            path = tmp_path / f"bit_{bit:04x}.exe"
            path.write_bytes(_pe_with_posture(dllchar=bit))
            facts = _pe_hardening_facts(path)
            assert facts[fact] is True, fact
            for other in bits.values():
                if other != fact:
                    assert facts[other] is False, f"{fact} leaked into {other}"

    def test_subsystem_values_read_as_their_names(self, tmp_path: Path) -> None:
        for value, name in ((1, "native"), (2, "gui"), (3, "console"), (10, "efi_application")):
            path = tmp_path / f"subsystem_{value}.exe"
            path.write_bytes(_pe_with_posture(subsystem=value))
            assert _pe_hardening_facts(path)["subsystem"] == name
        # An unmapped value still reads, numerically, rather than vanishing.
        path = tmp_path / "subsystem_42.exe"
        path.write_bytes(_pe_with_posture(subsystem=42))
        assert _pe_hardening_facts(path)["subsystem"] == "subsystem_42"

    def test_a_pe32_entry_rebases_off_the_narrow_image_base(self, tmp_path: Path) -> None:
        # PE32 keeps a 32-bit ImageBase at offset 28 (after BaseOfData); a
        # reader that assumed the PE32+ layout would rebase off garbage.
        path = tmp_path / "x86.exe"
        path.write_bytes(
            _pe_with_posture(entry_rva=0x1000, image_base=0x40_0000, magic=0x10B)
        )
        assert _pe_hardening_facts(path)["entry"] == 0x40_1000

    def test_a_zero_entry_rva_omits_the_entry_fact(self, tmp_path: Path) -> None:
        # AddressOfEntryPoint 0 is how a resource-only DLL declares "no entry";
        # reporting the bare image base would invent an address.
        path = tmp_path / "noentry.dll"
        path.write_bytes(_pe_with_posture(entry_rva=0))
        assert "entry" not in _pe_hardening_facts(path)

    def test_a_non_pe_reads_no_facts(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe at all")
        assert _pe_hardening_facts(path) == {}

    def test_an_optional_header_too_short_for_the_fields_reads_no_facts(
        self, tmp_path: Path
    ) -> None:
        # A 64-byte optional header ends before Subsystem/DllCharacteristics;
        # fail closed rather than reading past it.
        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x40)
        coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 64, 0)
        opt = bytearray(64)
        struct.pack_into("<H", opt, 0, 0x20B)
        path = tmp_path / "short.exe"
        path.write_bytes(bytes(dos) + coff + bytes(opt))
        assert _pe_hardening_facts(path) == {}

    def test_session_over_a_pe_carries_the_posture(self, tmp_path: Path) -> None:
        path = tmp_path / "app.exe"
        path.write_bytes(
            _pe_with_posture(subsystem=2, dllchar=0x0140, entry_rva=0x2000)
        )
        session = SessionRegistry().create(str(path))
        pe = session.metadata["pe"]
        assert pe["subsystem"] == "gui"
        assert pe["aslr"] is True
        assert pe["nx"] is True
        assert pe["cfg"] is False
        assert pe["entry"] == 0x1_4000_2000


def _pe_with_tls(
    *,
    callback_count: int = 0,
    magic: int = 0x20B,
    callbacks_va: int | None = None,
) -> bytes:
    """A minimal one-section PE whose TLS directory (index 9) carries callbacks.

    The section holds the IMAGE_TLS_DIRECTORY at its start and the
    AddressOfCallBacks array at +0x100; both the array field and each callback
    entry are VAs off the preferred image base, the layout the loader expects.
    ``callbacks_va`` overrides the AddressOfCallBacks field (0 declares no
    array; a below-base value makes it bogus).
    """
    image_base = 0x1_4000_0000 if magic == 0x20B else 0x40_0000
    ptr = 8 if magic == 0x20B else 4
    fmt = "<Q" if magic == 0x20B else "<I"
    sect_rva = 0x1000

    size = 0x100 + (callback_count + 1) * ptr
    sec = bytearray((max(size, 0x200) + 0x1FF) & ~0x1FF)
    for i in range(callback_count):
        struct.pack_into(fmt, sec, 0x100 + i * ptr, image_base + 0x2000 + i * 0x10)
    resolved_va = image_base + sect_rva + 0x100 if callbacks_va is None else callbacks_va
    dir_fmt = "<QQQQII" if magic == 0x20B else "<IIIIII"
    struct.pack_into(dir_fmt, sec, 0, 0, 0, 0, resolved_va, 0, 0)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    machine = 0x8664 if magic == 0x20B else 0x14C
    opt_size = 0xF0 if magic == 0x20B else 0xE0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0)
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
    tls_dir_size = 40 if magic == 0x20B else 24
    struct.pack_into("<II", opt, dir_count_off + 4 + 9 * 8, sect_rva, tls_dir_size)

    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders

    sect = bytearray(40)
    sect[0:4] = b".tls"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, len(sec))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0xC0000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


class TestPeTlsFacts:
    """_pe_tls_facts reads the TLS-callback surface -- the PE's code-before-main.

    The pair to the ELF/Mach-O init_funcs facts, the .NET module initializer
    and the Android custom Application class: the loader runs every TLS
    callback before the entry point, which is where a packer puts anti-debug
    checks. A present directory with zero callbacks is ordinary thread-local
    data; a nonzero count is code an entry-point-first analyst would miss.
    """

    def test_a_pe_without_a_tls_directory_reads_absent(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_tls_facts(path) == {"tls": {"present": False, "callbacks": 0}}

    def test_callbacks_count_off_a_pe32_plus_array(self, tmp_path: Path) -> None:
        path = tmp_path / "tls3.exe"
        path.write_bytes(_pe_with_tls(callback_count=3))
        assert _pe_tls_facts(path) == {"tls": {"present": True, "callbacks": 3}}

    def test_a_pe32_array_walks_at_the_narrow_pointer_width(self, tmp_path: Path) -> None:
        # PE32 TLS fields and callbacks are 4 bytes; a reader assuming PE32+
        # 8-byte slots would read the AddressOfCallBacks from the wrong field
        # and pair adjacent callbacks into one bogus pointer.
        path = tmp_path / "tls_x86.exe"
        path.write_bytes(_pe_with_tls(callback_count=2, magic=0x10B))
        assert _pe_tls_facts(path) == {"tls": {"present": True, "callbacks": 2}}

    def test_a_directory_declaring_no_array_reads_present_but_zero(
        self, tmp_path: Path
    ) -> None:
        # AddressOfCallBacks 0 is how plain thread-local data ships: TLS is
        # present, but there is no code-before-main to count.
        path = tmp_path / "tls_data.exe"
        path.write_bytes(_pe_with_tls(callbacks_va=0))
        assert _pe_tls_facts(path) == {"tls": {"present": True, "callbacks": 0}}

    def test_a_callbacks_va_below_the_image_base_reads_zero(self, tmp_path: Path) -> None:
        # A VA that cannot be rebased is a lying directory; fail closed to the
        # presence bit rather than mapping a negative RVA.
        path = tmp_path / "tls_bogus.exe"
        path.write_bytes(_pe_with_tls(callback_count=3, callbacks_va=0x1000))
        assert _pe_tls_facts(path) == {"tls": {"present": True, "callbacks": 0}}

    def test_the_callback_walk_is_bounded(self, tmp_path: Path) -> None:
        path = tmp_path / "tls_many.exe"
        path.write_bytes(_pe_with_tls(callback_count=80))
        facts = _pe_tls_facts(path)
        assert facts["tls"]["callbacks"] == 64  # _PE_MAX_TLS_CALLBACKS

    def test_a_non_pe_reads_no_facts(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe at all")
        assert _pe_tls_facts(path) == {}

    def test_session_over_a_pe_carries_the_tls_surface(self, tmp_path: Path) -> None:
        path = tmp_path / "app.exe"
        path.write_bytes(_pe_with_tls(callback_count=2))
        session = SessionRegistry().create(str(path))
        assert session.metadata["pe"]["tls"] == {"present": True, "callbacks": 2}


_GUID = "a1b2c3d4-e5f6-4788-99aa-bbccddeeff00"


def _rsds_blob(guid: str, age: int, path: str) -> bytes:
    """An RSDS CodeView blob: sig, mixed-endian GUID, age, NUL-terminated path."""
    return b"RSDS" + uuid.UUID(guid).bytes_le + age.to_bytes(4, "little") + path.encode() + b"\x00"


def _pe_with_debug(
    records: list[tuple[int, bytes]],
    *,
    zero_file_pointer: bool = False,
    declared_size: int | None = None,
) -> bytes:
    """A minimal one-section PE whose debug directory (index 6) holds ``records``.

    Each record is ``(type, blob)``; the IMAGE_DEBUG_DIRECTORY table sits at
    the section start with the blobs behind it, each entry carrying both the
    blob's RVA and its file pointer. ``zero_file_pointer`` leaves every
    PointerToRawData 0 so the reader must fall back to the RVA;
    ``declared_size`` overrides each entry's SizeOfData.
    """
    sect_rva = 0x1000
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0)
    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)

    table_size = len(records) * 28
    sec = bytearray(table_size)
    placed: list[tuple[int, int, int]] = []
    for dbg_type, blob in records:
        off = len(sec)
        sec.extend(blob)
        placed.append((dbg_type, off, len(blob)))
    for i, (dbg_type, off, size) in enumerate(placed):
        struct.pack_into(
            "<IIHHIIII",
            sec,
            i * 28,
            0,
            0,
            0,
            0,
            dbg_type,
            declared_size if declared_size is not None else size,
            sect_rva + off,
            0 if zero_file_pointer else raw_off + off,
        )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<Q", opt, 24, 0x1_4000_0000)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, sect_rva + 0x1000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112 + 6 * 8, sect_rva, table_size)  # debug dir

    sect = bytearray(40)
    sect[0:6] = b".rdata"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, (len(sec) + 0x1FF) & ~0x1FF)
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


class TestPeDebugFingerprint:
    """_pe_debug_fingerprint reads the CodeView RSDS record -- the PE build id.

    The pair to an ELF build-id and a Mach-O UUID, now tool-free for every PE:
    the per-build PDB GUID and age (whose concatenation is the symbol-server
    key) and the PDB path the linker baked in, which routinely leaks user and
    project names. No fingerprint is a real answer, so a debug-less PE simply
    carries no ``pdb`` fact.
    """

    def test_a_pe_without_a_debug_directory_has_no_fingerprint(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_debug_fingerprint(path) == {}

    def test_the_rsds_record_reads_guid_age_path_and_symbol_key(self, tmp_path: Path) -> None:
        path = tmp_path / "app.exe"
        path.write_bytes(_pe_with_debug([(2, _rsds_blob(_GUID, 3, r"C:\build\app.pdb"))]))
        assert _pe_debug_fingerprint(path) == {
            "pdb": {
                "guid": _GUID,
                "age": 3,
                "path": r"C:\build\app.pdb",
                # The symbol-server key: 32 upper-case GUID hex digits with the
                # age appended in hex -- what symstore names the directory.
                "signature": "A1B2C3D4E5F6478899AABBCCDDEEFF003",
            }
        }

    def test_non_codeview_records_are_stepped_over(self, tmp_path: Path) -> None:
        # A repro record (type 16) first, the CodeView record second: the walk
        # must key on the Type field, not assume the first entry.
        path = tmp_path / "repro.exe"
        path.write_bytes(
            _pe_with_debug(
                [(16, b"\x00" * 32), (2, _rsds_blob(_GUID, 1, "out.pdb"))]
            )
        )
        assert _pe_debug_fingerprint(path)["pdb"]["age"] == 1

    def test_a_foreign_codeview_signature_is_not_a_fingerprint(self, tmp_path: Path) -> None:
        # NB10 is the ancient PDB 2.0 shape; misreading its layout as RSDS
        # would fabricate a GUID from path bytes.
        path = tmp_path / "nb10.exe"
        path.write_bytes(_pe_with_debug([(2, b"NB10" + b"\x00" * 24)]))
        assert _pe_debug_fingerprint(path) == {}

    def test_a_zero_file_pointer_falls_back_to_the_rva(self, tmp_path: Path) -> None:
        # Some linkers leave PointerToRawData 0 and address the blob only by
        # RVA; the fingerprint must still resolve through the section table.
        path = tmp_path / "rva_only.exe"
        path.write_bytes(
            _pe_with_debug([(2, _rsds_blob(_GUID, 2, "a.pdb"))], zero_file_pointer=True)
        )
        assert _pe_debug_fingerprint(path)["pdb"]["age"] == 2

    def test_a_truncated_declared_size_is_skipped(self, tmp_path: Path) -> None:
        # SizeOfData smaller than sig+GUID+age cannot hold an RSDS record.
        path = tmp_path / "tiny.exe"
        path.write_bytes(
            _pe_with_debug([(2, _rsds_blob(_GUID, 1, "a.pdb"))], declared_size=10)
        )
        assert _pe_debug_fingerprint(path) == {}

    def test_a_non_pe_has_no_fingerprint(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe at all")
        assert _pe_debug_fingerprint(path) == {}

    def test_session_over_a_pe_carries_the_fingerprint(self, tmp_path: Path) -> None:
        path = tmp_path / "app.exe"
        path.write_bytes(_pe_with_debug([(2, _rsds_blob(_GUID, 3, r"C:\build\app.pdb"))]))
        session = SessionRegistry().create(str(path))
        assert session.metadata["pe"]["pdb"]["signature"] == "A1B2C3D4E5F6478899AABBCCDDEEFF003"

    def test_the_committed_fixture_fingerprint_matches_the_deep_reader(self) -> None:
        # The managed fixture bakes in a known RSDS record that dotnet.inspect
        # already reports; the session-level fact must read the same bytes.
        if not _DOTNET_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
        pdb = _pe_debug_fingerprint(_DOTNET_FIXTURE)["pdb"]
        assert pdb["guid"] == _GUID
        assert pdb["path"] == r"C:\build\headless\MyAssembly.pdb"


def _vs_node(
    key: str, value: bytes, value_len: int, children: list[bytes], w_type: int = 0
) -> bytes:
    """One VS_VERSIONINFO node: header, UTF-16 key, padded value, padded children."""
    body = bytearray(key.encode("utf-16-le") + b"\x00\x00")
    while (6 + len(body)) % 4:
        body += b"\x00"
    body += value
    for child in children:
        while (6 + len(body)) % 4:
            body += b"\x00"
        body += child
    return struct.pack("<HHH", 6 + len(body), value_len, w_type) + bytes(body)


def _vs_string(key: str, value: str) -> bytes:
    text = value.encode("utf-16-le") + b"\x00\x00"
    return _vs_node(key, text, len(value) + 1, [], w_type=1)  # wValueLength is in WCHARs


def _version_blob(
    *,
    file_version: tuple[int, int, int, int] = (1, 2, 3, 4),
    product_version: tuple[int, int, int, int] = (9, 8, 7, 6),
    strings: dict[str, str] | None = None,
    with_fixed: bool = True,
    root_key: str = "VS_VERSION_INFO",
) -> bytes:
    """A VS_VERSIONINFO blob with the given fixed versions and string table."""
    fixed = b""
    if with_fixed:
        fms = (file_version[0] << 16) | file_version[1]
        fls = (file_version[2] << 16) | file_version[3]
        pms = (product_version[0] << 16) | product_version[1]
        pls = (product_version[2] << 16) | product_version[3]
        fixed = struct.pack("<IIIIII", 0xFEEF04BD, 0x0001_0000, fms, fls, pms, pls)
        fixed += b"\x00" * 28  # flags/OS/type/date fields the reader ignores
    children: list[bytes] = []
    if strings:
        table = _vs_node("040904b0", b"", 0, [_vs_string(k, v) for k, v in strings.items()])
        children.append(_vs_node("StringFileInfo", b"", 0, [table]))
    return _vs_node(root_key, fixed, len(fixed), children)


class TestPeVersionInfo:
    """_pe_version_info reads VS_VERSIONINFO -- the PE's self-declared identity.

    The pair to an APK's package identity and a .NET assembly version: numeric
    file/product versions from VS_FIXEDFILEINFO plus the StringFileInfo table
    Explorer's Details pane shows. Self-declared, so a claim for triage --
    malware fakes a Microsoft identity here -- never a verdict.
    """

    def test_a_pe_without_resources_carries_no_identity(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_version_info(path) == {}

    def test_versions_and_strings_read_exactly(self, tmp_path: Path) -> None:
        blob = _version_blob(
            strings={
                "CompanyName": "Contoso Ltd",
                "ProductName": "Widget",
                "OriginalFilename": "widget.exe",
            }
        )
        path = tmp_path / "widget.exe"
        path.write_bytes(_pe_with_resources([(16, 1, blob)]))
        assert _pe_version_info(path) == {
            "version_info": {
                "file_version": "1.2.3.4",
                "product_version": "9.8.7.6",
                "strings": {
                    "CompanyName": "Contoso Ltd",
                    "ProductName": "Widget",
                    "OriginalFilename": "widget.exe",
                },
            }
        }

    def test_a_resource_without_fixed_info_still_reads_strings(self, tmp_path: Path) -> None:
        # Some resource editors drop VS_FIXEDFILEINFO but keep the strings;
        # the identity claim is the strings, so they must survive alone.
        blob = _version_blob(with_fixed=False, strings={"CompanyName": "Contoso Ltd"})
        path = tmp_path / "nofixed.exe"
        path.write_bytes(_pe_with_resources([(16, 1, blob)]))
        info = _pe_version_info(path)["version_info"]
        assert info["file_version"] is None
        assert info["strings"] == {"CompanyName": "Contoso Ltd"}

    def test_other_resources_without_rt_version_read_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest_only.exe"
        path.write_bytes(
            _pe_with_resources([(24, 1, b'<?xml version="1.0"?><assembly/>')])
        )
        assert _pe_version_info(path) == {}

    def test_a_foreign_root_key_is_not_version_info(self, tmp_path: Path) -> None:
        blob = _version_blob(root_key="NOT_VERSION_INFO", strings={"CompanyName": "X"})
        path = tmp_path / "foreign.exe"
        path.write_bytes(_pe_with_resources([(16, 1, blob)]))
        assert _pe_version_info(path) == {}

    def test_the_string_table_is_bounded(self, tmp_path: Path) -> None:
        blob = _version_blob(strings={f"Key{i:02d}": "v" for i in range(40)})
        path = tmp_path / "many.exe"
        path.write_bytes(_pe_with_resources([(16, 1, blob)]))
        info = _pe_version_info(path)["version_info"]
        assert len(info["strings"]) == 32  # _PE_MAX_VERSION_STRINGS

    def test_a_truncated_blob_fails_closed(self, tmp_path: Path) -> None:
        # The root declares a 52-byte fixed value the cut blob cannot hold:
        # nothing decodes, so no identity is claimed and nothing raises.
        blob = _version_blob(strings={"CompanyName": "Contoso Ltd"})[:30]
        path = tmp_path / "cut.exe"
        path.write_bytes(_pe_with_resources([(16, 1, blob)]))
        assert _pe_version_info(path) == {}

    def test_session_over_a_pe_carries_the_identity(self, tmp_path: Path) -> None:
        blob = _version_blob(strings={"CompanyName": "Contoso Ltd"})
        path = tmp_path / "app.exe"
        path.write_bytes(_pe_with_resources([(16, 1, blob)]))
        session = SessionRegistry().create(str(path))
        info = session.metadata["pe"]["version_info"]
        assert info["file_version"] == "1.2.3.4"
        assert info["strings"]["CompanyName"] == "Contoso Ltd"


def _pe_with_rich(
    entries: list[tuple[int, int, int]],
    *,
    key: int = 0x1F2E3D4C,
    corrupt_dans: bool = False,
    stray_rich: bool = False,
) -> bytes:
    """A minimal PE32 whose pre-header bytes carry a Rich header.

    ``entries`` are (product id, build, count) rows, masked the way MSVC's
    linker masks them: DanS ^ key at 0x80, three masked zeros, the pairs, the
    plain ``Rich`` marker and the plain key. ``corrupt_dans`` writes a wrong
    sentinel so the mask must be rejected; ``stray_rich`` plants only the
    marker text with no census behind it.
    """

    def mask(value: int) -> bytes:
        return (value ^ key).to_bytes(4, "little")

    if stray_rich:
        region = b"prose mentioning Rich" + key.to_bytes(4, "little") + b"\x00" * 3
    else:
        sentinel = 0x536E6144 ^ (0xFF if corrupt_dans else 0)
        region = mask(sentinel) + mask(0) * 3
        for product_id, build, count in entries:
            region += mask((product_id << 16) | build) + mask(count)
        region += b"Rich" + key.to_bytes(4, "little")
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    e_lfanew = 0x80 + ((len(region) + 7) & ~7)
    dos[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    stub = bytes(dos) + region + bytes(e_lfanew - 0x80 - len(region))
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    optional[0:2] = (0x10B).to_bytes(2, "little")  # PE32
    optional[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
    return stub + coff + bytes(optional)


def _pe_with_section_flags(sections: list[tuple[bytes, int]]) -> bytes:
    """A minimal PE32 whose section headers carry the given (name, characteristics)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, len(sections), 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    optional[0:2] = (0x10B).to_bytes(2, "little")  # PE32
    optional[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
    table = bytearray()
    for name, characteristics in sections:
        sect = bytearray(40)
        sect[0 : len(name)] = name
        struct.pack_into("<I", sect, 36, characteristics)
        table += sect
    return bytes(dos) + coff + bytes(optional) + bytes(table)


def _pe_with_section_data(sections: list[tuple[bytes, bytes]]) -> bytes:
    """A minimal PE32 whose sections carry the given (name, raw bytes)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, len(sections), 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    optional[0:2] = (0x10B).to_bytes(2, "little")  # PE32
    optional[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
    table = bytearray()
    payloads = bytearray()
    data_off = 0x40 + len(coff) + len(optional) + 40 * len(sections)
    for index, (name, payload) in enumerate(sections):
        sect = bytearray(40)
        sect[0 : len(name)] = name
        struct.pack_into("<I", sect, 8, len(payload))  # VirtualSize
        struct.pack_into("<I", sect, 12, 0x1000 * (index + 1))  # VirtualAddress
        struct.pack_into("<I", sect, 16, len(payload))  # SizeOfRawData
        struct.pack_into("<I", sect, 20, data_off + len(payloads))  # PointerToRawData
        table += sect
        payloads += payload
    return bytes(dos) + coff + bytes(optional) + bytes(table) + bytes(payloads)


class TestPeHighEntropySections:
    """_pe_high_entropy_sections flags near-random sections -- UPX1's shape.

    The PE arm of the entropy census: the packed payload the resource and
    section magic censuses cannot see when it ships compressed or encrypted.
    Measured over each section's raw file bytes, the same bytes pefile's
    get_entropy reads; an empty list is a real "nothing packed here" answer.
    """

    def test_a_planted_uniform_section_flags_at_eight(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.exe"
        path.write_bytes(
            _pe_with_section_data(
                [(b".text", b"\x90" * 512), (b"UPX1", bytes(range(256)) * 4)]
            )
        )
        assert _pe_high_entropy_sections(path) == {
            "high_entropy_sections": [{"section": "UPX1", "entropy": 8.0, "size": 1024}]
        }

    def test_ordinary_sections_stay_unflagged(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.exe"
        path.write_bytes(
            _pe_with_section_data(
                [(b".text", b"\x90\x55\x8b\xec\xc3" * 200), (b".rdata", b"version 1.0 " * 60)]
            )
        )
        assert _pe_high_entropy_sections(path) == {"high_entropy_sections": []}

    def test_a_sectionless_pe_lists_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_high_entropy_sections(path) == {"high_entropy_sections": []}

    def test_a_non_pe_reports_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "not.exe"
        path.write_bytes(b"\x7fELF" + bytes(0x100))
        assert _pe_high_entropy_sections(path) == {}

    def test_session_over_a_packed_shape_carries_the_flags(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.exe"
        path.write_bytes(_pe_with_section_data([(b"UPX1", bytes(range(256)) * 4)]))
        session = SessionRegistry().create(str(path))
        flags = session.metadata["pe"]["high_entropy_sections"]
        assert flags == [{"section": "UPX1", "entropy": 8.0, "size": 1024}]


class TestPeWxSections:
    """_pe_wx_sections names sections mapped writable and executable at once.

    The PE W^X violation, the pair to the ELF and Mach-O wx_segments counts:
    the shape a packer's unpack-into section takes (UPX0 famously) and no
    stock compiler emits. Named, because on PE the section name is the handle
    an analyst greps for; an empty list is a real "nothing writable runs".
    """

    _R = 0x4000_0000
    _W = 0x8000_0000
    _X = 0x2000_0000

    def test_a_sectionless_pe_lists_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_wx_sections(path) == {"wx_sections": []}

    def test_only_the_wx_section_is_named(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.exe"
        path.write_bytes(
            _pe_with_section_flags(
                [
                    (b".text", self._R | self._X),
                    (b"UPX0", self._R | self._W | self._X),
                    (b".data", self._R | self._W),
                ]
            )
        )
        assert _pe_wx_sections(path) == {"wx_sections": ["UPX0"]}

    def test_multiple_violations_list_in_table_order(self, tmp_path: Path) -> None:
        path = tmp_path / "multi.exe"
        path.write_bytes(
            _pe_with_section_flags(
                [
                    (b"UPX0", self._R | self._W | self._X),
                    (b".data", self._R | self._W),
                    (b"UPX1", self._R | self._W | self._X),
                ]
            )
        )
        assert _pe_wx_sections(path) == {"wx_sections": ["UPX0", "UPX1"]}

    def test_a_truncated_section_table_fails_closed(self, tmp_path: Path) -> None:
        raw = _pe_with_section_flags([(b"UPX0", self._R | self._W | self._X)])
        path = tmp_path / "cut.exe"
        path.write_bytes(raw[:-8])  # the table's last header is cut short
        assert _pe_wx_sections(path) == {"wx_sections": []}

    def test_a_non_pe_reports_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "not.exe"
        path.write_bytes(b"\x7fELF" + bytes(0x100))
        assert _pe_wx_sections(path) == {}

    def test_session_over_a_packed_shape_carries_the_census(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.exe"
        path.write_bytes(
            _pe_with_section_flags(
                [(b".text", self._R | self._X), (b"UPX0", self._R | self._W | self._X)]
            )
        )
        session = SessionRegistry().create(str(path))
        assert session.metadata["pe"]["wx_sections"] == ["UPX0"]


class TestPeRichHeader:
    """_pe_rich_header decodes MSVC's toolchain census -- the PE provenance.

    The pair to an ELF .comment, a Mach-O build-tool entry and the WASM
    producers section: one (product id, build, count) row per tool the
    Microsoft linker consumed objects from, XOR-masked between the DOS stub
    and the PE header. Only MSVC-family linkers write it, so absence is a
    real answer; the mask is trusted only once the DanS sentinel confirms it.
    """

    def test_a_pe_without_a_rich_header_reports_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_rich_header(path) == {}

    def test_planted_census_rows_decode_exactly(self, tmp_path: Path) -> None:
        path = tmp_path / "msvc.exe"
        path.write_bytes(_pe_with_rich([(0x104, 31933, 5), (0x0F2, 40116, 1)]))
        rich = _pe_rich_header(path)["rich_header"]
        assert rich["checksum"] == 0x1F2E3D4C
        assert rich["entries"] == [
            {"product_id": 0x104, "build": 31933, "count": 5},
            {"product_id": 0x0F2, "build": 40116, "count": 1},
        ]

    def test_an_empty_census_is_still_a_census(self, tmp_path: Path) -> None:
        # DanS immediately followed by Rich: present, zero rows -- distinct
        # from a PE with no Rich header at all.
        path = tmp_path / "empty.exe"
        path.write_bytes(_pe_with_rich([]))
        assert _pe_rich_header(path)["rich_header"]["entries"] == []

    def test_a_rich_marker_without_dans_is_not_a_census(self, tmp_path: Path) -> None:
        path = tmp_path / "prose.exe"
        path.write_bytes(_pe_with_rich([], stray_rich=True))
        assert _pe_rich_header(path) == {}

    def test_a_corrupt_sentinel_rejects_the_mask(self, tmp_path: Path) -> None:
        path = tmp_path / "corrupt.exe"
        path.write_bytes(_pe_with_rich([(0x104, 31933, 5)], corrupt_dans=True))
        assert _pe_rich_header(path) == {}

    def test_the_walk_is_bounded_at_the_entry_cap(self, tmp_path: Path) -> None:
        # 64 rows (the cap) decode; a census larger than the backwards-walk
        # bound never reaches its sentinel and fails closed.
        path = tmp_path / "cap.exe"
        path.write_bytes(_pe_with_rich([(i, i, 1) for i in range(64)]))
        assert len(_pe_rich_header(path)["rich_header"]["entries"]) == 64
        path.write_bytes(_pe_with_rich([(i, i, 1) for i in range(80)]))
        assert _pe_rich_header(path) == {}

    def test_a_non_pe_reports_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "not.exe"
        path.write_bytes(b"\x7fELF" + bytes(0x100))
        assert _pe_rich_header(path) == {}

    def test_session_over_a_rich_pe_carries_the_census(self, tmp_path: Path) -> None:
        path = tmp_path / "msvc.exe"
        path.write_bytes(_pe_with_rich([(0x105, 31937, 12)]))
        session = SessionRegistry().create(str(path))
        rich = session.metadata["pe"]["rich_header"]
        assert rich["entries"] == [{"product_id": 0x105, "build": 31937, "count": 12}]


class TestPeResourcePayloads:
    """_pe_resource_payloads lists executable magic hidden in the resources.

    The Windows dropper's stash: a nested PE in an RT_RCDATA blob it writes out
    and runs, an ELF for a cross-platform loader, a ZIP of tooling -- even a
    "bitmap" whose bytes are really an executable. Each flagged entry names the
    resource type it hid under, the sniffed kind and the byte size; benign
    resources (a manifest, an icon) are never listed.
    """

    def test_a_resourceless_pe_lists_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_resource_payloads(path) == ([], 0)

    def test_each_hidden_kind_reads_under_its_resource_type(self, tmp_path: Path) -> None:
        path = tmp_path / "dropper.exe"
        path.write_bytes(
            _pe_with_resources(
                [
                    (10, 101, _NESTED_PE),  # RT_RCDATA -> PE
                    (10, 102, b"\x7fELF" + b"\x00" * 20),  # RT_RCDATA -> ELF
                    (24, 1, b'<?xml version="1.0"?><assembly/>'),  # RT_MANIFEST -> XML
                    (2, 103, b"PK\x03\x04" + b"\x00" * 20),  # "bitmap" -> ZIP
                ]
            )
        )
        payloads, count = _pe_resource_payloads(path)
        assert count == 3
        listed = {(p["type"], p["name"]): p["kind"] for p in payloads}
        assert listed == {
            ("rcdata", "101"): "pe",
            ("rcdata", "102"): "elf",
            ("bitmap", "103"): "zip",
        }
        pe_entry = next(p for p in payloads if p["kind"] == "pe")
        assert pe_entry["size"] == len(_NESTED_PE)

    def test_prose_opening_with_mz_is_not_an_executable(self, tmp_path: Path) -> None:
        path = tmp_path / "prose.exe"
        path.write_bytes(_pe_with_resources([(10, 1, b"MZ region of the report")]))
        assert _pe_resource_payloads(path) == ([], 0)

    def test_a_resource_pointing_out_of_bounds_is_skipped(self, tmp_path: Path) -> None:
        # A data entry whose RVA lands outside the .rsrc section is malformed;
        # the walk skips it rather than reading arbitrary file bytes.
        raw = bytearray(_pe_with_resources([(10, 1, _NESTED_PE)]))
        # The single data entry's OffsetToData is the first RVA field inside the
        # .rsrc raw data; find .rsrc raw offset and rewrite the entry's RVA.
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        sect = e_lfanew + 4 + 20 + 0xF0
        raw_off = struct.unpack_from("<I", raw, sect + 20)[0]
        # Scan the .rsrc for the data entry whose size equals the payload.
        target = len(_NESTED_PE)
        for probe in range(raw_off, len(raw) - 8, 4):
            if struct.unpack_from("<I", raw, probe + 4)[0] == target:
                struct.pack_into("<I", raw, probe, 0x7000_0000)  # RVA far outside .rsrc
                break
        path = tmp_path / "oob.exe"
        path.write_bytes(bytes(raw))
        assert _pe_resource_payloads(path) == ([], 0)

    def test_the_list_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        resources = [(10, 200 + i, b"\x7fELF" + b"\x00" * 20) for i in range(80)]
        path = tmp_path / "many.exe"
        path.write_bytes(_pe_with_resources(resources))
        payloads, count = _pe_resource_payloads(path)
        assert count == 80
        assert len(payloads) == 64

    def test_non_pe_lists_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe, just bytes")
        assert _pe_resource_payloads(path) == ([], 0)


class TestDotnetResourcePayloads:
    """_dotnet_resource_payloads lists executable magic in managed resources.

    The .NET packer's store: the real, often encrypted, stage-two assembly kept
    as an embedded ManifestResource and loaded with Assembly.Load at runtime.
    Each flagged entry names the resource, the sniffed kind and the byte size;
    the committed fixture's benign config.json never lists, and a resource
    forwarded to another file (a non-null Implementation) is not embedded here.
    """

    def test_the_committed_fixture_carries_no_executable_resource(self) -> None:
        if not _DOTNET_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
        # config.json is benign JSON: a real embedded resource, correctly not
        # flagged -- the census is a magic sniff, not a "has resources" bit.
        assert _dotnet_resource_payloads(_DOTNET_FIXTURE) == ([], 0)

    def test_each_planted_kind_reads_under_its_resource_name(self, tmp_path: Path) -> None:
        nested = _nested_assembly_bytes()
        path = tmp_path / "packed.exe"
        path.write_bytes(
            _dotnet_with_resources(
                [
                    ("stage2.dll", nested),  # a nested PE (the packed assembly)
                    ("loader.elf", b"\x7fELF" + b"\x00" * 0x40),
                    ("assets.zip", b"PK\x03\x04" + b"\x00" * 0x40),
                    ("config.json", b'{"mode": "real"}'),  # benign: not flagged
                ]
            )
        )
        payloads, count = _dotnet_resource_payloads(path)
        assert count == 3
        listed = {p["name"]: p["kind"] for p in payloads}
        assert listed == {"stage2.dll": "pe", "loader.elf": "elf", "assets.zip": "zip"}
        stage2 = next(p for p in payloads if p["name"] == "stage2.dll")
        assert stage2["size"] == len(nested)

    def test_prose_opening_with_mz_is_not_an_executable(self, tmp_path: Path) -> None:
        path = tmp_path / "prose.exe"
        path.write_bytes(_dotnet_with_resources([("notes.txt", b"MZ is a person's initials")]))
        assert _dotnet_resource_payloads(path) == ([], 0)

    def test_the_list_is_bounded_but_the_count_exact(self, tmp_path: Path) -> None:
        resources = [(f"blob{i:03d}.bin", b"\x7fELF" + b"\x00" * 0x20) for i in range(80)]
        path = tmp_path / "many.exe"
        path.write_bytes(_dotnet_with_resources(resources))
        payloads, count = _dotnet_resource_payloads(path)
        assert count == 80
        assert len(payloads) == 64

    def test_a_native_pe_has_no_managed_resources(self, tmp_path: Path) -> None:
        # No CLI header at all: the .NET census must bail cleanly, not read the
        # PE resource tree by mistake.
        path = tmp_path / "native.exe"
        path.write_bytes(_native_pe())
        assert _dotnet_resource_payloads(path) == ([], 0)

    def test_session_over_a_packed_assembly_carries_the_census(self, tmp_path: Path) -> None:
        nested = _nested_assembly_bytes()
        path = tmp_path / "packed.exe"
        path.write_bytes(_dotnet_with_resources([("stage2.dll", nested)]))
        session = SessionRegistry().create(str(path))
        dotnet = session.metadata["dotnet"]
        assert dotnet["is_dotnet"] is True
        assert dotnet["resource_payload_count"] == 1
        assert dotnet["resource_payloads"] == [
            {"name": "stage2.dll", "kind": "pe", "size": len(nested)}
        ]


class TestDotnetHighEntropyResources:
    """_dotnet_high_entropy_resources flags near-random magicless resources.

    The exact ConfuserEx / .NET-Reactor shape: the protected stage-two
    assembly is stored encrypted as a ManifestResource and inflated at
    runtime behind Assembly.Load, so it opens with no magic and only the
    Shannon measure gives it away. Self-declaring heads route to their own
    census; an empty list is a real "nothing encrypted here" answer.
    """

    def test_a_planted_uniform_resource_flags_at_eight(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.exe"
        path.write_bytes(
            _dotnet_with_resources(
                [("enc.bin", bytes(range(256)) * 4), ("config.json", b'{"mode": "real"}')]
            )
        )
        assert _dotnet_high_entropy_resources(path) == (
            [{"name": "enc.bin", "entropy": 8.0, "size": 1024}],
            1,
        )

    def test_a_self_declaring_head_routes_to_its_own_census(self, tmp_path: Path) -> None:
        blob = bytes(range(256)) * 4
        path = tmp_path / "declared.exe"
        path.write_bytes(
            _dotnet_with_resources(
                [
                    ("stage2.dll", _nested_assembly_bytes()),  # payload census's beat
                    ("strings.resources", b"\xce\xca\xef\xbe" + blob),  # ResourceManager
                    ("icon.png", b"\x89PNG\r\n\x1a\n" + blob),  # media explains itself
                ]
            )
        )
        assert _dotnet_high_entropy_resources(path) == ([], 0)
        payloads, _count = _dotnet_resource_payloads(path)
        assert [p["name"] for p in payloads] == ["stage2.dll"]

    def test_a_resource_below_the_size_floor_is_not_measured(self, tmp_path: Path) -> None:
        path = tmp_path / "tiny.exe"
        path.write_bytes(_dotnet_with_resources([("tiny.bin", bytes(range(128)))]))
        assert _dotnet_high_entropy_resources(path) == ([], 0)

    def test_the_committed_fixture_carries_no_opaque_resource(self) -> None:
        if not _DOTNET_FIXTURE.is_file():
            pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
        assert _dotnet_high_entropy_resources(_DOTNET_FIXTURE) == ([], 0)

    def test_session_over_a_protected_shape_carries_the_flags(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.exe"
        path.write_bytes(_dotnet_with_resources([("enc.bin", bytes(range(256)) * 4)]))
        session = SessionRegistry().create(str(path))
        dotnet = session.metadata["dotnet"]
        assert dotnet["high_entropy_resource_count"] == 1
        assert dotnet["high_entropy_resources"] == [
            {"name": "enc.bin", "entropy": 8.0, "size": 1024}
        ]


def test_native_pe_has_no_dotnet_block(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    path.write_bytes(_native_pe())
    # No COM descriptor directory: describe_pe_clr must return nothing so the PE
    # baseline session carries no spurious metadata.
    assert describe_pe_clr(path) == {}


def test_non_pe_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "notpe.bin"
    path.write_bytes(b"this is not a PE file at all")
    assert describe_pe_clr(path) == {}


def test_session_over_the_dotnet_fixture_carries_the_facts() -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    session = SessionRegistry().create(str(_DOTNET_FIXTURE))
    assert session.target is TargetKind.PE
    assert session.metadata["dotnet"]["is_dotnet"] is True
    assert session.metadata["dotnet"]["metadata_version"] == "v4.0.30319"


def test_session_over_a_native_pe_carries_only_the_authenticode_verdict(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    path.write_bytes(_native_pe())
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.PE
    assert session.architecture is Architecture.X86
    # A native PE has no .NET block, but it does now carry the whole-PE
    # Authenticode verdict -- unsigned here, a real answer rather than empty --
    # an (empty) resource-payload census, an (empty) import/export surface, the
    # optional-header posture (all-zero fields: unknown subsystem, no
    # mitigations, no declared entry), the (absent) TLS-callback surface and
    # an (empty) W^X section census.
    assert session.metadata == {
        "pe": {
            "authenticode": {"signed": False},
            "resource_payloads": [],
            "resource_payload_count": 0,
            "imports": [],
            "exports": [],
            "subsystem": "unknown",
            "os_version": "0.0",
            "subsystem_version": "0.0",
            "high_entropy_va": False,
            "aslr": False,
            "force_integrity": False,
            "nx": False,
            "no_seh": False,
            "appcontainer": False,
            "cfg": False,
            "tls": {"present": False, "callbacks": 0},
            "wx_sections": [],
            "high_entropy_sections": [],
        }
    }


def test_session_over_a_signed_pe_carries_the_authenticode_range(tmp_path: Path) -> None:
    path = tmp_path / "signed.exe"
    path.write_bytes(_sign_native_pe(payload=b"PKCS7-BODY"))
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.PE
    assert session.metadata["pe"]["authenticode"]["signed"] is True
    assert session.metadata["pe"]["authenticode"]["authenticode"] is True
