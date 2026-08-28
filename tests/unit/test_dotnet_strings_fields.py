"""dotnet.strings decodes the #US user-string heap (ldstr literals).

dotnet.enumerate kind="strings" walks #Strings (metadata identifier names);
dotnet.strings decodes the separate #US heap, where a program's actual string
constants live. These build a #US heap by hand and drive the decoder through a
fake metadata context (compressed length forms, terminal-byte stripping,
UTF-16LE decode, empty-blob skip, the collect cap and per-string clip), then
cover name_filter/min_length/paging, a real no-#US-heap session (routing +
has_us_heap False), and the tool docstring / read-only classification.
"""

from __future__ import annotations

import ast
import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet import metadata_enum
from headless_re_mcp.dotnet.metadata_enum import (
    _collect_user_strings,
    _decompress_uint,
    _MetaCtx,
    enumerate_user_strings,
)
from headless_re_mcp.tools.core import build_dotnet_tools


def _tool_docstring(func_name: str) -> str:
    source = Path(build_dotnet_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return ast.get_docstring(node) or ""
    return ""


def _compress(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    return bytes(
        [0xC0 | (n >> 24), (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
    )


def _us_entry(text: str) -> bytes:
    body = text.encode("utf-16-le")
    # Terminal flag byte: 1 if any char is non-ASCII, else 0 (decoder ignores it).
    terminal = b"\x01" if any(ord(ch) > 0x7F for ch in text) else b"\x00"
    blob = body + terminal
    return _compress(len(blob)) + blob


def _us_heap(*texts: str) -> bytes:
    # Offset 0 is the empty blob (single 0x00), then packed entries.
    heap = b"\x00"
    for text in texts:
        heap += _us_entry(text)
    return heap


def _ctx(heap: bytes, *, with_us: bool = True) -> _MetaCtx:
    prefix = b"BSJBpad!"  # arbitrary bytes before the heap in the metadata blob
    meta = prefix + heap
    stream_map = {"#US": (len(prefix), len(heap))} if with_us else {}
    return _MetaCtx(
        path=Path("fake.exe"),
        pe_data=b"",
        layout=None,
        meta=meta,
        stream_map=stream_map,
        tables=b"",
        strings=b"",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={},
        table_data_offset=0,
    )


def _run(ctx: _MetaCtx, monkeypatch, **kwargs) -> dict:
    monkeypatch.setattr(metadata_enum, "inspect_dotnet", lambda *a, **k: None)
    monkeypatch.setattr(metadata_enum, "_load_metadata_context", lambda p: ctx)
    return enumerate_user_strings("fake.exe", **kwargs)


def test_decompress_uint_forms() -> None:
    assert _decompress_uint(bytes([0x03]), 0) == (3, 1)
    assert _decompress_uint(bytes([0x7F]), 0) == (0x7F, 1)
    # Two-byte form encodes 0x80..0x3FFF.
    assert _decompress_uint(bytes([0x80, 0xC9]), 0) == (201, 2)
    # Four-byte form.
    assert _decompress_uint(bytes([0xC0, 0x00, 0x40, 0x00]), 0) == (0x4000, 4)
    # Truncated buffers return None rather than raising.
    assert _decompress_uint(bytes([0x80]), 0) is None
    assert _decompress_uint(b"", 0) is None


def test_collect_decodes_entries_and_offsets() -> None:
    heap = _us_heap("https://api.example.com/v1", "hi")
    rows, capped = _collect_user_strings(_ctx(heap))
    assert capped is False
    assert [r["value"] for r in rows] == ["https://api.example.com/v1", "hi"]
    # First entry begins right after the empty blob at offset 0.
    assert rows[0]["offset"] == 1
    assert rows[0]["token"] == (0x70000000 | 1)
    assert rows[0]["char_length"] == len("https://api.example.com/v1")
    # Offsets are packed and monotonically increasing.
    assert rows[1]["offset"] > rows[0]["offset"]


def test_collect_handles_two_byte_length_and_unicode() -> None:
    long_text = "A" * 200  # blob length 401 -> two-byte compressed prefix
    heap = _us_heap(long_text, "café")
    rows, _ = _collect_user_strings(_ctx(heap))
    assert rows[0]["value"] == long_text
    assert rows[0]["char_length"] == 200
    assert rows[1]["value"] == "café"


def test_collect_skips_empty_and_stops_on_malformed() -> None:
    # Empty blob only -> nothing.
    rows, capped = _collect_user_strings(_ctx(b"\x00"))
    assert rows == [] and capped is False
    # A length prefix that overruns the heap is clipped to what is there and the
    # walk terminates (no crash, no infinite loop) rather than reading past end.
    heap = b"\x00" + _compress(50) + "xy".encode("utf-16-le")
    rows, capped = _collect_user_strings(_ctx(heap))
    assert capped is False
    assert rows and rows[0]["value"].startswith("x")


def test_collect_respects_cap(monkeypatch) -> None:
    monkeypatch.setattr(metadata_enum, "MAX_US_STRINGS", 2)
    heap = _us_heap("one", "two", "three")
    rows, capped = _collect_user_strings(_ctx(heap))
    assert len(rows) == 2
    assert capped is True


def test_collect_clips_long_string(monkeypatch) -> None:
    monkeypatch.setattr(metadata_enum, "MAX_US_STRING_CHARS", 4)
    heap = _us_heap("abcdefgh")
    rows, _ = _collect_user_strings(_ctx(heap))
    assert rows[0]["value"] == "abcd"
    assert rows[0]["truncated"] is True
    assert rows[0]["char_length"] == 8


def test_enumerate_no_us_heap_is_soft(monkeypatch) -> None:
    out = _run(_ctx(b"", with_us=False), monkeypatch)
    assert out["has_us_heap"] is False
    assert out["items"] == []
    assert out["total"] == 0
    assert out["kind"] == "userstrings"
    assert out["not_ida_idalib"] is True
    assert out["claims_universal_unpack"] is False


def test_enumerate_name_filter_and_min_length(monkeypatch) -> None:
    heap = _us_heap("https://a.example", "x", "HTTPS://B.example", "short")
    out = _run(_ctx(heap), monkeypatch, name_filter="https://")
    # Case-insensitive substring match, applied before paging.
    assert out["total"] == 2
    assert {r["value"] for r in out["items"]} == {
        "https://a.example",
        "HTTPS://B.example",
    }
    out2 = _run(_ctx(heap), monkeypatch, min_length=5)
    assert {r["value"] for r in out2["items"]} == {
        "https://a.example",
        "HTTPS://B.example",
        "short",
    }


def test_enumerate_paging(monkeypatch) -> None:
    heap = _us_heap(*[f"s{i:03d}" for i in range(10)])
    page = _run(_ctx(heap), monkeypatch, offset=0, limit=4)
    assert page["total"] == 10
    assert len(page["items"]) == 4
    assert page["truncated"] is True
    tail = _run(_ctx(heap), monkeypatch, offset=8, limit=4)
    assert len(tail["items"]) == 2
    assert tail["truncated"] is False


def _write_minimal_clr(path: Path) -> None:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_service_dotnet_strings_no_heap(tmp_path: Path) -> None:
    binary = tmp_path / "empty.exe"
    _write_minimal_clr(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        result = service.dotnet_strings(session_id, limit=5)
        assert result.ok
        assert result.data is not None
        assert result.data["kind"] == "userstrings"
        assert result.data["has_us_heap"] is False
        assert result.data["items"] == []
        assert result.data["not_ida_idalib"] is True
    finally:
        service.close_all()


def test_dotnet_strings_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("dotnet_strings").split())
    assert "#US" in doc
    assert "ldstr" in doc
    assert "token" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "dotnet.strings" in _READ_ONLY_NAMES
