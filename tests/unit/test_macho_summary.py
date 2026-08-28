"""The stdlib Mach-O readers (summarize_macho, list_macho_symbols) and routing.

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
-- a macOS dylib, an iOS app's main binary, a Mach-O malware sample -- was the
one native format that could not be opened here at all. The header, load
commands and LC_SYMTAB nlist array are exact structures. These tests pin the
readers on hand-assembled Mach-O images (portable, so they run on Windows CI too
where no real Mach-O exists): a 64-bit LE dylib with segments/dylibs/rpath/uuid/
platform/symtab, an executable with PIE/LC_MAIN/encryption-info, a 32-bit
big-endian image, a fat binary with per-slice summaries, the LC_SYMTAB symbol
page with its import/export classification and library resolution (64- and
32-bit nlist), honest pagination, the code-signature decode (CodeDirectory
identity/team/flags/cdhash, entitlements plist, adhoc vs hardened-runtime vs
linker-signed verdicts, unsigned images, corrupt superblobs), resilience to
truncated load commands, out-of-file slices and symbol records, refusal of a
non-Mach-O (including a Java class file that shares the 0xcafebabe magic), and
the service routing that turns a bad file into a precise envelope rather than a
fault.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.macho import (
    MachoParseError,
    list_macho_symbols,
    read_macho_signature,
    summarize_macho,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
_MAGIC_32_LE = b"\xce\xfa\xed\xfe"
_MAGIC_32_BE = b"\xfe\xed\xfa\xce"
_FAT_MAGIC = b"\xca\xfe\xba\xbe"


def _cmd(cmd_id: int, body: bytes) -> bytes:
    size = 8 + len(body)
    pad = (-size) % 8
    return struct.pack("<II", cmd_id, size + pad) + body + b"\x00" * pad


def _dylib_cmd(cmd_id: int, name: str) -> bytes:
    return _cmd(cmd_id, struct.pack("<IIII", 24, 0, 0x10000, 0x10000) + name.encode() + b"\x00")


def _segment64(name: bytes, prot: int, nsects: int) -> bytes:
    body = struct.pack(
        "<16sQQQQiiII", name, 0x100000000, 0x4000, 0, 0x4000, prot, prot, nsects, 0
    )
    return _cmd(0x19, body)


def _build_dylib64() -> bytes:
    """An arm64 LE dylib: segments, id/load/weak dylibs, rpath, uuid, iOS target."""
    commands = [
        _segment64(b"__TEXT", 0x5, 2),
        _segment64(b"__DATA", 0x3, 1),
        _dylib_cmd(0xD, "libfix.dylib"),
        _dylib_cmd(0xC, "/usr/lib/libSystem.B.dylib"),
        _dylib_cmd(0x80000018, "libweak.dylib"),
        _cmd(0x8000001C, struct.pack("<I", 12) + b"@loader_path/../Frameworks\x00"),
        _cmd(0x1B, bytes(range(16))),
        _cmd(0x32, struct.pack("<IIII", 2, 0x000E0000, 0x00110200, 0)),  # iOS 14.0 / sdk 17.2
        _cmd(0x2, struct.pack("<IIII", 0, 5, 0, 0)),  # LC_SYMTAB, 5 symbols
        _cmd(0x1D, struct.pack("<II", 0, 0)),  # LC_CODE_SIGNATURE
    ]
    payload = b"".join(commands)
    header = _MAGIC_64_LE + struct.pack(
        "<iiIIIII", 0x0100000C, 0, 6, len(commands), len(payload), 0, 0
    )
    return header + payload


def _build_executable64(*, encrypted: bool = True) -> bytes:
    """An x86-64 LE PIE executable with LC_MAIN and iOS store encryption info."""
    commands = [
        _segment64(b"__TEXT", 0x5, 3),
        _cmd(0x80000028, struct.pack("<QQ", 0x4000, 0)),  # LC_MAIN
        _cmd(0x2C, struct.pack("<IIII", 0x4000, 0x8000, 1 if encrypted else 0, 0)),
    ]
    payload = b"".join(commands)
    header = _MAGIC_64_LE + struct.pack(
        "<iiIIIII", 0x01000007, 0, 2, len(commands), len(payload), 0x200000, 0
    )
    return header + payload


def _build_ppc32_be() -> bytes:
    """A 32-bit big-endian PowerPC executable with one LC_SEGMENT."""
    body = struct.pack(">16sIIIIiiII", b"__TEXT", 0x1000, 0x2000, 0, 0x2000, 0x5, 0x5, 1, 0)
    command = struct.pack(">II", 0x1, 8 + len(body)) + body
    header = _MAGIC_32_BE + struct.pack(">iiIIII", 18, 0, 2, 1, len(command), 0)
    return header + command


def _build_fat(slices: list[bytes]) -> bytes:
    header_size = 8 + 20 * len(slices)
    placed: list[tuple[int, int]] = []
    offset = header_size
    for image in slices:
        placed.append((offset, len(image)))
        offset += len(image)
    records = b""
    for image, (off, size) in zip(slices, placed, strict=True):
        (cputype,) = struct.unpack_from("<i", image, 4)
        records += struct.pack(">iiIII", cputype, 0, off, size, 0)
    return _FAT_MAGIC + struct.pack(">I", len(slices)) + records + b"".join(slices)


def test_dylib_full_summary() -> None:
    out = summarize_macho(_build_dylib64())
    assert out["format"] == "Mach-O"
    assert out["fat"] is False
    assert out["bits"] == 64
    assert out["endianness"] == "little"
    assert out["cpu"] == "AArch64"
    assert out["filetype"] == "dylib"
    assert out["pie"] is False
    assert [s["name"] for s in out["segments"]] == ["__TEXT", "__DATA"]
    assert out["segments"][0]["prot"] == "r-x"
    assert out["segments"][1]["prot"] == "rw-"
    assert out["id_dylib"] == "libfix.dylib"
    assert out["dylibs"] == ["/usr/lib/libSystem.B.dylib", "libweak.dylib"]
    assert out["rpaths"] == ["@loader_path/../Frameworks"]
    assert out["uuid"] == bytes(range(16)).hex()
    assert out["platform"] == {"name": "iOS", "min_os": "14.0.0", "sdk": "17.2.0"}
    assert out["symbol_count"] == 5
    assert out["stripped"] is False
    assert out["signed"] is True
    assert out["encrypted"] is False
    assert out["entry_offset"] is None
    assert out["warnings"] == []


def test_executable_pie_main_and_encryption() -> None:
    out = summarize_macho(_build_executable64())
    assert out["cpu"] == "x86-64"
    assert out["filetype"] == "executable"
    assert out["pie"] is True
    assert out["entry_offset"] == 0x4000
    assert out["encrypted"] is True
    assert out["signed"] is False
    assert out["symbol_count"] is None
    assert out["stripped"] is True  # no LC_SYMTAB at all


def test_unencrypted_cryptid_zero() -> None:
    out = summarize_macho(_build_executable64(encrypted=False))
    assert out["encrypted"] is False


def test_32bit_big_endian() -> None:
    out = summarize_macho(_build_ppc32_be())
    assert out["bits"] == 32
    assert out["endianness"] == "big"
    assert out["cpu"] == "PowerPC"
    assert out["filetype"] == "executable"
    assert [s["name"] for s in out["segments"]] == ["__TEXT"]


def test_fat_binary_lists_slices() -> None:
    out = summarize_macho(_build_fat([_build_executable64(), _build_dylib64()]))
    assert out["fat"] is True
    assert out["slice_count"] == 2
    assert [s["cpu"] for s in out["slices"]] == ["x86-64", "AArch64"]
    inner = out["slices"][1]["summary"]
    assert inner["filetype"] == "dylib"
    assert inner["dylibs"] == ["/usr/lib/libSystem.B.dylib", "libweak.dylib"]


def test_fat_slice_past_eof_is_reported_not_fatal() -> None:
    data = bytearray(_build_fat([_build_executable64()]))
    struct.pack_into(">I", data, 8 + 12, 0xFFFFFF00)  # fat_arch.size -> past EOF

    out = summarize_macho(bytes(data))
    assert out["slices"][0]["error"] == "slice extends past end of file"
    assert "summary" not in out["slices"][0]


def test_a_truncated_load_command_is_a_warning() -> None:
    whole = _build_dylib64()
    out = summarize_macho(whole[: len(whole) - 40])
    assert any("past end of file" in w for w in out["warnings"])
    assert out["cpu"] == "AArch64"  # the header still reads


def test_an_impossible_command_size_is_a_warning() -> None:
    data = bytearray(_build_dylib64())
    struct.pack_into("<I", data, 32 + 4, 2)  # first command's cmdsize -> 2
    out = summarize_macho(bytes(data))
    assert any("impossible size" in w for w in out["warnings"])


@pytest.mark.parametrize(
    "blob",
    [b"", b"\x00" * 64, b"MZ\x00\x00" + b"\x00" * 60, b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56],
)
def test_non_macho_raises(blob: bytes) -> None:
    with pytest.raises(MachoParseError):
        summarize_macho(blob)


def test_a_java_class_file_is_refused_by_name() -> None:
    java = _FAT_MAGIC + struct.pack(">HH", 0, 67) + b"\x00" * 64  # minor 0, major 67
    with pytest.raises(MachoParseError, match="Java class"):
        summarize_macho(java)


def test_a_fat_with_no_slices_is_refused() -> None:
    with pytest.raises(MachoParseError, match="no architecture"):
        summarize_macho(_FAT_MAGIC + struct.pack(">I", 0))


# --- LC_SYMTAB symbols --------------------------------------------------------


def _build_symbolic(*, bits: int = 64) -> bytes:
    """A little-endian dylib with an LC_SYMTAB: one import per kind and an export.

    Two dylib dependencies make the library ordinals resolvable (ordinal 1 =
    libSystem, ordinal 2 = libweak). The five nlist entries are: an undefined
    external from ordinal 1, an undefined external via dynamic_lookup, a defined
    external (exported), a defined local, and a debug stab.
    """
    magic = _MAGIC_64_LE if bits == 64 else _MAGIC_32_LE
    cputype = 0x0100000C if bits == 64 else 7

    strtab = bytearray(b"\x00")

    def add(text: str) -> int:
        off = len(strtab)
        strtab.extend(text.encode() + b"\x00")
        return off

    off_malloc = add("_malloc")
    off_dyn = add("_PyInit_x")
    off_export = add("_myfunc")
    off_local = add("_local")
    off_stab = add("stab.c")

    # n_type: N_EXT=0x01, N_SECT|N_EXT=0x0f, N_SECT=0x0e, N_FUN stab=0x24.
    entries = [
        (off_malloc, 0x01, 0, (1 << 8), 0),  # undefined external, ordinal 1
        (off_dyn, 0x01, 0, (0xFE << 8), 0),  # undefined external, dynamic_lookup
        (off_export, 0x0F, 1, 0, 0x1000),  # defined external -> exported
        (off_local, 0x0E, 1, 0, 0x2000),  # defined local
        (off_stab, 0x24, 1, 0, 0x3000),  # debug stab
    ]
    nl_fmt = "<IBBHQ" if bits == 64 else "<IBBHI"
    nlist = b"".join(struct.pack(nl_fmt, *entry) for entry in entries)

    dylib_cmds = [
        _dylib_cmd(0xC, "/usr/lib/libSystem.B.dylib"),
        _dylib_cmd(0x80000018, "libweak.dylib"),
    ]
    hdr_size = 32 if bits == 64 else 28
    payload_len = sum(len(c) for c in dylib_cmds) + 24  # + LC_SYMTAB (24 bytes)
    symoff = hdr_size + payload_len
    stroff = symoff + len(nlist)
    symtab_cmd = _cmd(0x2, struct.pack("<IIII", symoff, len(entries), stroff, len(strtab)))
    commands = [*dylib_cmds, symtab_cmd]
    payload = b"".join(commands)
    assert len(payload) == payload_len

    if bits == 64:
        header = magic + struct.pack(
            "<iiIIIII", cputype, 0, 6, len(commands), len(payload), 0, 0
        )
    else:
        header = magic + struct.pack("<iiIIII", cputype, 0, 6, len(commands), len(payload), 0)
    return header + payload + nlist + bytes(strtab)


def test_symbols_are_classified_and_libraries_resolved() -> None:
    out = list_macho_symbols(_build_symbolic())
    assert out["format"] == "Mach-O"
    assert out["fat"] is False
    assert out["cpu"] == "AArch64"
    assert out["symbols_total"] == 5
    assert out["symbols_listed"] == 5
    assert out["imported_listed"] == 2
    assert out["exported_listed"] == 1

    by_name = {s["name"]: s for s in out["symbols"]}
    malloc = by_name["_malloc"]
    assert malloc["imported"] is True and malloc["exported"] is False
    assert malloc["external"] is True
    assert malloc["type"] == "undefined"
    assert malloc["library_ordinal"] == 1
    assert malloc["library"] == "/usr/lib/libSystem.B.dylib"

    dyn = by_name["_PyInit_x"]
    assert dyn["imported"] is True
    assert dyn["library"] == "dynamic_lookup"

    exported = by_name["_myfunc"]
    assert exported["exported"] is True and exported["imported"] is False
    assert exported["type"] == "section"
    assert exported["value"] == "0x1000"
    assert "library" not in exported

    local = by_name["_local"]
    assert local["external"] is False
    assert local["imported"] is False and local["exported"] is False

    stab = by_name["stab.c"]
    assert stab["type"] == "debug"
    assert stab["external"] is False


def test_symbols_32bit_nlist_path() -> None:
    out = list_macho_symbols(_build_symbolic(bits=32))
    assert out["cpu"] == "x86"
    assert out["symbols_total"] == 5
    by_name = {s["name"]: s for s in out["symbols"]}
    assert by_name["_malloc"]["library"] == "/usr/lib/libSystem.B.dylib"
    assert by_name["_myfunc"]["exported"] is True


def test_symbols_paginate_honestly() -> None:
    data = _build_symbolic()
    page = list_macho_symbols(data, offset=0, limit=2)
    assert [s["name"] for s in page["symbols"]] == ["_malloc", "_PyInit_x"]
    assert page["has_more"] is True
    tail = list_macho_symbols(data, offset=4, limit=10)
    assert [s["name"] for s in tail["symbols"]] == ["stab.c"]
    assert tail["has_more"] is False
    past = list_macho_symbols(data, offset=99, limit=10)
    assert past["symbols"] == []
    assert past["has_more"] is False


def test_no_symtab_is_an_empty_listing_with_a_warning() -> None:
    out = list_macho_symbols(_build_executable64())  # segment/LC_MAIN/encryption only
    assert out["symbols"] == []
    assert out["symbols_total"] == 0
    assert any("LC_SYMTAB" in w for w in out["warnings"])


def test_fat_symbols_read_first_slice() -> None:
    out = list_macho_symbols(_build_fat([_build_symbolic(), _build_executable64()]))
    assert out["fat"] is True
    assert out["arch"] == "AArch64"
    assert out["available_arches"] == ["AArch64", "x86-64"]
    assert out["exported_listed"] == 1
    assert any("fat binary" in w for w in out["warnings"])


def test_a_symbol_record_past_eof_is_a_warning() -> None:
    data = bytearray(_build_symbolic())
    # Point LC_SYMTAB's nsyms absurdly high without extending the file.
    marker = struct.pack("<II", 0x2, 24)
    pos = data.find(marker)
    struct.pack_into("<I", data, pos + 8 + 4, 100000)  # nsyms field
    out = list_macho_symbols(bytes(data))
    assert out["symbols_total"] == 100000
    assert out["symbols_listed"] < 100000
    assert any("past end of file" in w for w in out["warnings"])


def test_list_symbols_rejects_non_macho() -> None:
    with pytest.raises(MachoParseError):
        list_macho_symbols(b"MZ\x00\x00" + b"\x00" * 60)


# --- code signature (LC_CODE_SIGNATURE) -----------------------------------------

_ENTITLEMENTS_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
    b' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0"><dict>'
    b"<key>com.apple.security.get-task-allow</key><true/>"
    b"<key>application-identifier</key><string>TEAMID1234.com.example.gate</string>"
    b"</dict></plist>"
)


def _cs_blob(magic: int, content: bytes) -> bytes:
    return struct.pack(">II", magic, 8 + len(content)) + content


def _code_directory(
    *, flags: int, identifier: str = "com.example.gate", team: str | None = None
) -> bytes:
    """A version-0x20200 CodeDirectory with no hash slots: identity and flags."""
    ident_bytes = identifier.encode() + b"\x00"
    team_bytes = (team.encode() + b"\x00") if team else b""
    head = 52  # 44 fixed + scatterOffset + teamOffset
    ident_off = head
    team_off = head + len(ident_bytes) if team else 0
    length = head + len(ident_bytes) + len(team_bytes)
    fixed = struct.pack(
        ">IIIIIIIIIBBBBI",
        0xFADE0C02,  # CSMAGIC_CODEDIRECTORY
        length,
        0x20200,
        flags,
        length,  # hashOffset: no slots, points at the end
        ident_off,
        0,  # nSpecialSlots
        0,  # nCodeSlots
        0x4000,  # codeLimit
        32,
        2,  # hashType sha256
        0,  # platform
        12,  # pageSize log2 -> 4096
        0,  # spare2
    )
    return fixed + struct.pack(">II", 0, team_off) + ident_bytes + team_bytes


def _superblob(entries: list[tuple[int, bytes]]) -> bytes:
    offset = 12 + 8 * len(entries)
    index = b""
    body = b""
    for slot_type, blob in entries:
        index += struct.pack(">II", slot_type, offset)
        body += blob
        offset += len(blob)
    return struct.pack(">III", 0xFADE0CC0, offset, len(entries)) + index + body


def _build_signed_dylib(sig: bytes) -> bytes:
    """An arm64 dylib whose LC_CODE_SIGNATURE points at ``sig`` appended at EOF."""

    def commands(dataoff: int) -> list[bytes]:
        return [
            _segment64(b"__TEXT", 0x5, 1),
            _dylib_cmd(0xC, "/usr/lib/libSystem.B.dylib"),
            _cmd(0x1D, struct.pack("<II", dataoff, len(sig))),
        ]

    payload = b"".join(commands(0))
    payload = b"".join(commands(32 + len(payload)))
    header = _MAGIC_64_LE + struct.pack(
        "<iiIIIII", 0x0100000C, 0, 6, 3, len(payload), 0, 0
    )
    return header + payload + sig


def test_signature_full_decode() -> None:
    cd = _code_directory(flags=0x10000, team="TEAMID1234")  # RUNTIME
    sig = _superblob(
        [
            (0, cd),
            (2, _cs_blob(0xFADE0C01, b"\x00\x00\x00\x00")),  # requirements
            (5, _cs_blob(0xFADE7171, _ENTITLEMENTS_XML)),
            (0x10000, _cs_blob(0xFADE0B01, b"\x30\x82" + b"\x00" * 62)),  # CMS
        ]
    )
    out = read_macho_signature(_build_signed_dylib(sig))
    assert out["signed"] is True
    directory = out["code_directory"]
    assert directory["identifier"] == "com.example.gate"
    assert directory["team_id"] == "TEAMID1234"
    assert directory["flags"] == ["RUNTIME"]
    assert directory["hash_type"] == "sha256"
    assert directory["page_size"] == 4096
    assert directory["cdhash"] == hashlib.sha256(cd).digest()[:20].hex()
    assert out["adhoc"] is False
    assert out["hardened_runtime"] is True
    assert out["linker_signed"] is False
    assert out["has_requirements"] is True
    assert out["has_der_entitlements"] is False
    assert out["cms_signature_size"] == 64
    entitlements = out["entitlements"]
    assert entitlements["com.apple.security.get-task-allow"] is True
    assert entitlements["application-identifier"] == "TEAMID1234.com.example.gate"
    slot_names = [s["slot"] for s in out["slots"]]
    assert slot_names == ["code_directory", "requirements", "entitlements", "cms_signature"]
    assert out["warnings"] == []


def test_adhoc_linker_signed_has_no_team_and_no_cms() -> None:
    sig = _superblob([(0, _code_directory(flags=0x20002))])  # ADHOC | LINKER_SIGNED
    out = read_macho_signature(_build_signed_dylib(sig))
    assert out["adhoc"] is True
    assert out["linker_signed"] is True
    assert out["hardened_runtime"] is False
    assert out["code_directory"]["team_id"] is None
    assert out["cms_signature_size"] == 0
    assert out["entitlements"] is None


def test_unsigned_images_say_so() -> None:
    absent = read_macho_signature(_build_executable64())  # no LC_CODE_SIGNATURE
    assert absent["signed"] is False
    assert absent["code_directory"] is None
    assert absent["adhoc"] is None
    assert any("unsigned" in w for w in absent["warnings"])

    empty = read_macho_signature(_build_dylib64())  # LC_CODE_SIGNATURE, datasize 0
    assert empty["signed"] is False
    assert any("unsigned" in w for w in empty["warnings"])


def test_signature_region_past_eof_is_a_warning() -> None:
    sig = _superblob([(0, _code_directory(flags=0x2))])
    data = bytearray(_build_signed_dylib(sig))
    marker = struct.pack("<II", 0x1D, 16)
    pos = data.find(marker)
    struct.pack_into("<I", data, pos + 8, 0xFFFFFF00)  # dataoff -> past EOF
    out = read_macho_signature(bytes(data))
    assert out["signed"] is False
    assert any("past end of file" in w for w in out["warnings"])


def test_wrong_superblob_magic_is_a_warning() -> None:
    out = read_macho_signature(_build_signed_dylib(b"\xde\xad\xbe\xef" + b"\x00" * 12))
    assert out["signed"] is True  # the command is there, the region is not a superblob
    assert out["code_directory"] is None
    assert any("wrong magic" in w for w in out["warnings"])


def test_a_slot_pointing_past_the_region_is_skipped() -> None:
    sig = struct.pack(">III", 0xFADE0CC0, 20, 1) + struct.pack(">II", 0, 0xFFFF)
    out = read_macho_signature(_build_signed_dylib(sig))
    assert out["signed"] is True
    assert out["code_directory"] is None
    assert any("points past the region end" in w for w in out["warnings"])


def test_bad_entitlements_plist_is_a_warning() -> None:
    sig = _superblob(
        [
            (0, _code_directory(flags=0x2)),
            (5, _cs_blob(0xFADE7171, b"this is not xml at all")),
        ]
    )
    out = read_macho_signature(_build_signed_dylib(sig))
    assert out["entitlements"] is None
    assert any("did not parse" in w for w in out["warnings"])


def test_fat_signature_reads_first_slice() -> None:
    signed = _build_signed_dylib(_superblob([(0, _code_directory(flags=0x2))]))
    out = read_macho_signature(_build_fat([signed, _build_executable64()]))
    assert out["fat"] is True
    assert out["arch"] == "AArch64"
    assert out["available_arches"] == ["AArch64", "x86-64"]
    assert out["signed"] is True
    assert out["adhoc"] is True
    assert any("fat binary" in w for w in out["warnings"])


def test_signature_rejects_non_macho() -> None:
    with pytest.raises(MachoParseError):
        read_macho_signature(b"MZ\x00\x00" + b"\x00" * 60)


# --- service routing ----------------------------------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_a_macho(tmp_path: Path) -> None:
    binary = tmp_path / "libfix.dylib"
    binary.write_bytes(_build_dylib64())
    result = _service(tmp_path).macho_summary(str(binary))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["cpu"] == "AArch64"
    assert result.data["id_dylib"] == "libfix.dylib"


def test_service_refuses_a_non_macho(tmp_path: Path) -> None:
    junk = tmp_path / "not.dylib"
    junk.write_bytes(b"this is not a mach-o binary")
    result = _service(tmp_path).macho_summary(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).macho_summary(str(tmp_path / "nope.dylib"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_refuses_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.core.service_macho as service_macho

    monkeypatch.setattr(service_macho, "MACHO_SUMMARY_MAX_BYTES", 16)
    binary = tmp_path / "libfix.dylib"
    binary.write_bytes(_build_dylib64())
    result = _service(tmp_path).macho_summary(str(binary))
    assert not result.ok
    assert result.error.code == "too_large"


def test_service_lists_symbols(tmp_path: Path) -> None:
    binary = tmp_path / "libsym.dylib"
    binary.write_bytes(_build_symbolic())
    result = _service(tmp_path).macho_symbols(str(binary), offset=0, limit=2)
    assert result.ok, result.model_dump(mode="json")
    assert [s["name"] for s in result.data["symbols"]] == ["_malloc", "_PyInit_x"]
    assert result.data["has_more"] is True


def test_service_symbols_refuses_a_non_macho(tmp_path: Path) -> None:
    junk = tmp_path / "not.dylib"
    junk.write_bytes(b"this is not a mach-o binary")
    result = _service(tmp_path).macho_symbols(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_symbols_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).macho_symbols(str(tmp_path / "nope.dylib"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_reads_a_signature(tmp_path: Path) -> None:
    binary = tmp_path / "libsigned.dylib"
    binary.write_bytes(
        _build_signed_dylib(_superblob([(0, _code_directory(flags=0x2, team="TEAMID1234"))]))
    )
    result = _service(tmp_path).macho_signature(str(binary))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["adhoc"] is True
    assert result.data["code_directory"]["team_id"] == "TEAMID1234"


def test_service_signature_refuses_a_non_macho(tmp_path: Path) -> None:
    junk = tmp_path / "not.dylib"
    junk.write_bytes(b"this is not a mach-o binary")
    result = _service(tmp_path).macho_signature(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_signature_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).macho_signature(str(tmp_path / "nope.dylib"))
    assert not result.ok
    assert result.error.code == "not_found"
