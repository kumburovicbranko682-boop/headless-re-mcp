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

from headless_re_mcp.backends.common.dex import (
    DexParseError,
    list_dex_classes,
    summarize_dex,
)
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


# --- class table (list_dex_classes / dex.classes) -----------------------------

_NO_INDEX = 0xFFFFFFFF


def _build_classy_dex(
    strings: list[str],
    types: list[int],
    classes: list[dict[str, int | None]],
    version: bytes = b"035",
) -> bytes:
    """A DEX with real string, type and class_def tables.

    ``types`` maps a type index to a string index (the descriptor). Each class is
    ``{class_type, access, super_type, source}`` where class_type/super_type are
    type indices (super_type None -> NO_INDEX) and source is a string index
    (None -> NO_INDEX).
    """
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + len(strings) * 4
    class_defs_off = type_ids_off + len(types) * 4
    data_start = class_defs_off + len(classes) * 32
    blobs = bytearray()
    offsets: list[int] = []
    for text in strings:
        offsets.append(data_start + len(blobs))
        blobs += _uleb(len(text)) + text.encode("utf-8") + b"\x00"
    string_ids = b"".join(struct.pack("<I", off) for off in offsets)
    type_ids = b"".join(struct.pack("<I", t) for t in types)
    class_defs = bytearray()
    for cls in classes:
        super_type = cls.get("super_type")
        source = cls.get("source")
        class_defs += struct.pack(
            "<8I",
            int(cls["class_type"] or 0),
            int(cls.get("access") or 0),
            _NO_INDEX if super_type is None else int(super_type),
            0,
            _NO_INDEX if source is None else int(source),
            0,
            0,
            0,
        )
    body = string_ids + type_ids + bytes(class_defs) + bytes(blobs)
    header = bytearray(header_size)
    header[0:8] = b"dex\n" + version + b"\x00"
    struct.pack_into("<I", header, 0x08, 0x1234ABCD)
    header[0x0C:0x20] = bytes(range(20))
    fields = [
        header_size + len(body), header_size, 0x12345678, 0, 0, 0,
        len(strings), string_ids_off,
        len(types), type_ids_off,
        0, 0, 0, 0, 0, 0,
        len(classes), class_defs_off,
        0, 0,
    ]
    struct.pack_into("<20I", header, 0x20, *fields)
    return bytes(header) + body


_CLASSY_STRINGS = [
    "Lcom/example/Foo;",
    "Landroid/app/Activity;",
    "Ljava/lang/Object;",
    "Foo.java",
    "Lcom/example/Bar;",
]
_CLASSY_TYPES = [0, 1, 2, 4]
_CLASSY_CLASSES: list[dict[str, int | None]] = [
    {"class_type": 0, "access": 0x1 | 0x10, "super_type": 1, "source": 3},
    {"class_type": 3, "access": 0x1 | 0x200 | 0x400, "super_type": None, "source": None},
]


def _classy_dex() -> bytes:
    return _build_classy_dex(_CLASSY_STRINGS, _CLASSY_TYPES, _CLASSY_CLASSES)


def test_classes_are_resolved() -> None:
    out = list_dex_classes(_classy_dex())
    assert out["classes_total"] == 2
    assert out["has_more"] is False
    foo, bar = out["classes"]
    assert foo["descriptor"] == "Lcom/example/Foo;"
    assert foo["name"] == "com.example.Foo"
    assert foo["superclass"] == "Landroid/app/Activity;"
    assert foo["access_flags"] == ["public", "final"]
    assert foo["source_file"] == "Foo.java"
    # A NO_INDEX superclass (java.lang.Object) is null, not an error; no source.
    assert bar["name"] == "com.example.Bar"
    assert bar["superclass"] is None
    assert bar["access_flags"] == ["public", "interface", "abstract"]
    assert bar["source_file"] is None
    assert out["warnings"] == []


def test_classes_are_paginated_honestly() -> None:
    out = list_dex_classes(_classy_dex(), offset=1, limit=1)
    assert out["offset"] == 1
    assert out["classes_count"] == 1
    assert out["classes_total"] == 2
    assert out["has_more"] is False
    assert out["classes"][0]["name"] == "com.example.Bar"
    tail = list_dex_classes(_classy_dex(), offset=99, limit=5)
    assert tail["classes"] == []
    assert tail["has_more"] is False


def test_a_corrupt_class_type_index_is_a_warning() -> None:
    data = bytearray(_classy_dex())
    class_defs_off = 0x70 + len(_CLASSY_STRINGS) * 4 + len(_CLASSY_TYPES) * 4
    struct.pack_into("<I", data, class_defs_off, 999)  # class_idx past type table
    out = list_dex_classes(bytes(data))
    assert out["classes"][0]["descriptor"] == ""
    assert any("out of bounds" in w for w in out["warnings"])


def test_a_dex_with_no_classes_lists_empty() -> None:
    out = list_dex_classes(_build_classy_dex(["Lx;"], [], []))
    assert out["classes"] == []
    assert out["classes_total"] == 0
    assert out["has_more"] is False


@pytest.mark.parametrize("blob", [b"", b"NOTA" + b"\x00" * 120])
def test_list_classes_rejects_non_dex(blob: bytes) -> None:
    with pytest.raises(DexParseError):
        list_dex_classes(blob)


def test_service_lists_classes(tmp_path: Path) -> None:
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_classy_dex())
    result = _service(tmp_path).dex_classes(str(dex))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["classes_total"] == 2
    assert {c["name"] for c in result.data["classes"]} == {
        "com.example.Foo",
        "com.example.Bar",
    }


def test_service_class_listing_refuses_non_dex(tmp_path: Path) -> None:
    junk = tmp_path / "classes.dex"
    junk.write_bytes(b"not a dalvik executable")
    result = _service(tmp_path).dex_classes(str(junk))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_class_listing_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).dex_classes(str(tmp_path / "nope.dex"))
    assert not result.ok
    assert result.error.code == "not_found"
