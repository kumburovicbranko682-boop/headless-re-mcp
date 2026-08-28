"""Tests for WasmClient.data, the Data-section raw-bytes reader.

Like the strings/summary/names tests these build tiny modules by hand so the
parser runs with no wabt: wasm.data reads the module binary's data segments
directly and hands back their raw bytes (the bytes a printable-strings pass
cannot show), plus a lightweight map of every segment.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


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


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + (1).to_bytes(4, "little") + b"".join(sections)


def _vec_bytes(blob: bytes) -> bytes:
    return _uleb(len(blob)) + blob


def _i32_offset(value: int) -> bytes:
    return b"\x41" + _sleb(value) + b"\x0b"


def _data_active(offset: int, blob: bytes) -> bytes:
    return _uleb(0) + _i32_offset(offset) + _vec_bytes(blob)


def _data_passive(blob: bytes) -> bytes:
    return _uleb(1) + _vec_bytes(blob)


def _data_active_mem(memidx: int, offset: int, blob: bytes) -> bytes:
    return _uleb(2) + _uleb(memidx) + _i32_offset(offset) + _vec_bytes(blob)


def _data_section(*segments: bytes) -> bytes:
    return _section(11, _uleb(len(segments)) + b"".join(segments))


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _data(tmp_path: Path, data: bytes, **kw: object) -> dict:
    return WasmClient().data(_write(tmp_path, data), **kw)  # type: ignore[arg-type]


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_reads_active_segment_bytes_and_the_map(tmp_path: Path) -> None:
    """The headline case: an active segment's raw bytes plus the segment map.

    The bytes include non-printable values a strings pass would never surface,
    which is the whole reason the raw reader exists; they must round-trip exactly
    through the hex encoding.
    """
    blob = bytes([0x00, 0xFF, 0x01, 0x02]) + b"KEY" + bytes([0x00, 0xDE, 0xAD])
    base = 0x100
    out = _data(tmp_path, _module(_data_section(_data_active(base, blob))))

    assert out["module"] == "m.wasm"
    assert out["version"] == 1
    assert out["data_segments"] == 1
    # The map is metadata only -- no bytes ride in the segment index.
    assert out["segments"] == [
        {"index": 0, "mode": "active", "memory_offset": base, "size": len(blob)}
    ]
    # The selected segment (default 0) carries the raw bytes as hex.
    assert out["segment"] == 0
    assert out["mode"] == "active"
    assert out["memory_offset"] == base
    assert out["size"] == len(blob)
    assert out["encoding"] == "hex"
    assert bytes.fromhex(out["data"]) == blob
    assert out["byte_offset"] == 0
    assert out["count"] == len(blob)
    assert out["has_more"] is False


def test_passive_segment_has_null_memory_offset(tmp_path: Path) -> None:
    """A passive segment is not placed in memory, so memory_offset is null."""
    blob = bytes([0x10, 0x20, 0x30, 0x40])
    out = _data(tmp_path, _module(_data_section(_data_passive(blob))))
    assert out["segments"][0]["mode"] == "passive"
    assert out["segments"][0]["memory_offset"] is None
    assert out["mode"] == "passive"
    assert out["memory_offset"] is None
    assert bytes.fromhex(out["data"]) == blob


def test_global_get_base_is_active_but_unknown_offset(tmp_path: Path) -> None:
    """An active segment based on an imported global has no static offset."""
    segment = _uleb(0) + b"\x23" + _uleb(0) + b"\x0b" + _vec_bytes(b"\x01\x02based")
    out = _data(tmp_path, _module(_data_section(segment)))
    assert out["segments"][0]["mode"] == "active"
    assert out["segments"][0]["memory_offset"] is None
    assert out["mode"] == "active"
    assert out["memory_offset"] is None


def test_selects_a_specific_segment(tmp_path: Path) -> None:
    """segment picks which segment's bytes come back; the map lists all."""
    first = b"\x00first\x00"
    second = b"\xffsecond\xff"
    out = _data(
        tmp_path,
        _module(
            _data_section(
                _data_active(0, first),
                _data_active_mem(0, 0x2000, second),
            )
        ),
        segment=1,
    )
    assert out["data_segments"] == 2
    assert {s["index"] for s in out["segments"]} == {0, 1}
    assert out["segment"] == 1
    assert out["memory_offset"] == 0x2000
    assert bytes.fromhex(out["data"]) == second
    assert out["size"] == len(second)


def test_byte_window_pages_a_segment(tmp_path: Path) -> None:
    """offset/limit window into one segment; has_more says when bytes remain."""
    blob = bytes(range(20))
    module = _module(_data_section(_data_active(0, blob)))

    head = _data(tmp_path, module, segment=0, offset=0, limit=8)
    assert bytes.fromhex(head["data"]) == blob[:8]
    assert head["count"] == 8
    assert head["byte_offset"] == 0
    assert head["has_more"] is True

    tail = _data(tmp_path, module, segment=0, offset=16, limit=8)
    assert bytes.fromhex(tail["data"]) == blob[16:20]
    assert tail["count"] == 4
    assert tail["has_more"] is False

    # Reading at or past the end is a clean empty window, not an error.
    past = _data(tmp_path, module, segment=0, offset=100, limit=8)
    assert past["data"] == ""
    assert past["count"] == 0
    assert past["has_more"] is False


def test_limit_is_capped_at_the_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller cannot pull more than the per-window byte ceiling in one call."""
    monkeypatch.setattr(jsre_client, "_MAX_WASM_DATA_SEG_BYTES", 4)
    blob = bytes(range(10))
    out = _data(tmp_path, _module(_data_section(_data_active(0, blob))), segment=0, limit=1000)
    assert out["count"] == 4
    assert bytes.fromhex(out["data"]) == blob[:4]
    assert out["has_more"] is True


def test_no_data_section_is_empty_map_not_error(tmp_path: Path) -> None:
    """A module with no Data section is a clean empty map, not a fault."""
    out = _data(tmp_path, _module(_section(1, _uleb(0))))  # type section, no data
    assert out["segments"] == []
    assert out["data_segments"] == 0
    assert out["count"] == 0
    assert "data" not in out
    assert "segment" not in out


def test_segment_out_of_range_is_invalid_params(tmp_path: Path) -> None:
    """Asking for a segment a module does not have is invalid_params."""
    with pytest.raises(JsReError) as excinfo:
        _data(tmp_path, _module(_data_section(_data_active(0, b"only"))), segment=5)
    assert excinfo.value.code == "invalid_params"
    assert excinfo.value.details.get("data_segments") == 1


def test_segment_map_truncation_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module with more segments than the map cap trims and discloses it.

    The reader still resolves a segment past the map cap -- the trim bounds the
    map's size, it does not hide segments from the byte reader.
    """
    monkeypatch.setattr(jsre_client, "_MAX_WASM_DATA_SEGMENTS", 2)
    module = _module(
        _data_section(
            _data_active(0, b"\x00seg0"),
            _data_active(0x10, b"\x01seg1"),
            _data_active(0x20, b"\x02seg2"),
        )
    )
    out = _data(tmp_path, module, segment=2)
    assert len(out["segments"]) == 2
    assert out["segments_truncated"] is True
    assert out["segments_total"] == 3
    assert out["segments_limit"] == 2
    assert out["data_segments"] == 3
    # Segment 2 is past the trimmed map but still readable.
    assert out["segment"] == 2
    assert bytes.fromhex(out["data"]) == b"\x02seg2"


def test_bad_magic_is_a_clean_backend_error(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        _data(tmp_path, b"\x7fELF not a wasm module")
    assert excinfo.value.code == "backend_error"
    assert "WebAssembly" in excinfo.value.message


def test_segment_bytes_overrun_is_a_clean_backend_error(tmp_path: Path) -> None:
    segment = _uleb(0) + _i32_offset(0) + _uleb(200) + b"short"
    with pytest.raises(JsReError) as excinfo:
        _data(tmp_path, _module(_data_section(segment)))
    assert excinfo.value.code == "backend_error"


def test_unsupported_const_expr_is_a_clean_backend_error(tmp_path: Path) -> None:
    segment = _uleb(0) + b"\xd2" + _uleb(0) + b"\x0b" + _vec_bytes(b"x")
    with pytest.raises(JsReError) as excinfo:
        _data(tmp_path, _module(_data_section(segment)))
    assert excinfo.value.code == "backend_error"


def test_needs_no_wabt(tmp_path: Path) -> None:
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    client._decompile = None
    assert client.available is False
    blob = bytes([0x00, 0x01, 0x02, 0x03])
    out = client.data(_write(tmp_path, _module(_data_section(_data_active(0, blob)))))
    assert bytes.fromhex(out["data"]) == blob


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().data(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_docstring_names_the_contract_fields() -> None:
    doc = _tool_docstring("wasm.data")
    for token in (
        "segments",
        "memory_offset",
        "data",
        "has_more",
        "passive",
        "wasm.strings",
    ):
        assert token in doc, token
