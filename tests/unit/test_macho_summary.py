"""The stdlib Mach-O reader (summarize_macho) and macho.summary service routing.

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
-- a macOS dylib, an iOS app's main binary, a Mach-O malware sample -- was the
one native format that could not be opened here at all. The header and load
commands are exact structures. These tests pin the reader on hand-assembled
Mach-O images (portable, so they run on Windows CI too where no real Mach-O
exists): a 64-bit LE dylib with segments/dylibs/rpath/uuid/platform/symtab, an
executable with PIE/LC_MAIN/encryption-info, a 32-bit big-endian image, a fat
binary with per-slice summaries, resilience to truncated load commands and
out-of-file slices, refusal of a non-Mach-O (including a Java class file that
shares the 0xcafebabe magic), and the service routing that turns a bad file
into a precise envelope rather than a fault.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.macho import MachoParseError, summarize_macho
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_MAGIC_64_LE = b"\xcf\xfa\xed\xfe"
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
