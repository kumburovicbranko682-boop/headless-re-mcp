"""The stdlib standalone-.dex reader (summarize_dex) and dex.summary routing.

The apk.* tools drive androguard against an APK container; a lone .dex -- dropped
by malware, loaded at runtime, or pulled out of an APK -- had no reader here, and
androguard is not always installed. The DEX header is a fixed record and the
string table is a plain offset array into MUTF-8, both exact. These tests pin the
reader on a hand-assembled DEX, its section counts, the paginated string page,
its resilience to a corrupt string offset (a warning, not an exception), its
refusal of a non-DEX, and the service routing that turns a bad file into a
precise envelope rather than a fault.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.dex import DexParseError, summarize_dex
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _build_dex(strings: list[str], version: bytes = b"035") -> bytes:
    header_size = 0x70
    string_ids_off = header_size
    data_start = string_ids_off + len(strings) * 4
    blobs = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(data_start + len(blobs))
        blobs += _uleb(len(text)) + text.encode("utf-8") + b"\x00"
    string_ids = b"".join(struct.pack("<I", off) for off in offsets)
    body = string_ids + bytes(blobs)
    total = header_size + len(body)
    header = bytearray(header_size)
    header[0:8] = b"dex\n" + version + b"\x00"
    struct.pack_into("<I", header, 0x08, 0x1234ABCD)
    header[0x0C:0x20] = bytes(range(20))
    fields = [
        total, header_size, 0x12345678, 0, 0, 0,
        len(strings), string_ids_off,
        3, 0, 2, 0, 4, 0, 5, 0, 1, 0, 0, 0,
    ]
    struct.pack_into("<20I", header, 0x20, *fields)
    return bytes(header) + body


_STRINGS = ["Lcom/example/Foo;", "hello", "<init>", "https://evil.example/c2"]


def test_full_summary() -> None:
    out = summarize_dex(_build_dex(_STRINGS))
    assert out["version"] == "035"
    assert out["checksum"] == "0x1234abcd"
    assert len(out["signature"]) == 40
    assert out["endian"] == "little"
    assert out["actual_size"] == out["file_size"]
    assert out["counts"] == {
        "strings": 4,
        "types": 3,
        "protos": 2,
        "fields": 4,
        "methods": 5,
        "classes": 1,
    }
    assert out["strings"] == _STRINGS
    assert out["strings_total"] == 4
    assert out["has_more"] is False
    assert out["warnings"] == []


def test_string_table_is_paginated_honestly() -> None:
    out = summarize_dex(_build_dex(_STRINGS), offset=2, limit=1)
    assert out["offset"] == 2
    assert out["limit"] == 1
    assert out["strings"] == ["<init>"]
    assert out["strings_count"] == 1
    assert out["strings_total"] == 4
    assert out["has_more"] is True
    # offset past the end is an empty page, not an error.
    tail = summarize_dex(_build_dex(_STRINGS), offset=99, limit=10)
    assert tail["strings"] == []
    assert tail["has_more"] is False


def test_a_corrupt_string_offset_is_a_warning_not_a_crash() -> None:
    data = bytearray(_build_dex(_STRINGS))
    struct.pack_into("<I", data, 0x70, 0xFFFFFF)  # first string-id points past EOF
    out = summarize_dex(bytes(data))
    assert "hello" in out["strings"]  # the rest still read
    assert any("out of bounds" in w for w in out["warnings"])


def test_long_strings_are_bounded() -> None:
    out = summarize_dex(_build_dex(["z" * 20000]))
    assert len(out["strings"][0]) == 4096


def test_a_reverse_endian_tag_is_flagged() -> None:
    data = bytearray(_build_dex(_STRINGS))
    struct.pack_into("<I", data, 0x28, 0x78563412)  # endian_tag field
    out = summarize_dex(bytes(data))
    assert out["endian"] == "big"
    assert any("big-endian" in w for w in out["warnings"])


@pytest.mark.parametrize(
    "blob",
    [b"", b"dex\n035\x00" + b"\x00" * 10, b"NOTA" + b"\x00" * 120, b"\x00" * 200],
)
def test_non_dex_files_raise(blob: bytes) -> None:
    with pytest.raises(DexParseError):
        summarize_dex(blob)


# --- service routing ----------------------------------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_a_dex(tmp_path: Path) -> None:
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_build_dex(_STRINGS))
    result = _service(tmp_path).dex_summary(str(dex))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["counts"]["strings"] == 4
    assert "Lcom/example/Foo;" in result.data["strings"]


def test_service_refuses_a_non_dex(tmp_path: Path) -> None:
    junk = tmp_path / "classes.dex"
    junk.write_bytes(b"this is not a dalvik executable")
    result = _service(tmp_path).dex_summary(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).dex_summary(str(tmp_path / "nope.dex"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_refuses_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.core.service_apk as service_apk

    monkeypatch.setattr(service_apk, "DEX_SUMMARY_MAX_BYTES", 16)
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_build_dex(_STRINGS))
    result = _service(tmp_path).dex_summary(str(dex))
    assert not result.ok
    assert result.error.code == "too_large"
