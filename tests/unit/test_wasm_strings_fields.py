"""Tests for WasmClient.strings, the Data-section string extractor.

Like the summary/names tests these build tiny modules by hand so the parser runs
with no wabt: wasm.strings reads the module binary's data segments directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient


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


def _strings(tmp_path: Path, data: bytes, **kw: object) -> dict:
    return WasmClient().strings(_write(tmp_path, data), **kw)  # type: ignore[arg-type]


def test_extracts_active_segment_strings_with_absolute_offsets(tmp_path: Path) -> None:
    """The headline case: printable runs in a data segment, located in memory."""
    s1 = b"https://x.test/v1"
    s2 = b"short"
    s3 = b"AUTHKEY=abcdef"
    blob = b"\x01\x02" + s1 + b"\x00" + s2 + b"\x00\xff\xff" + s3
    off1 = 2
    off2 = off1 + len(s1) + 1
    off3 = off2 + len(s2) + 3
    base = 0x100

    data = _strings(tmp_path, _module(_data_section(_data_active(base, blob))))

    assert data["module"] == "m.wasm"
    assert data["version"] == 1
    assert data["data_segments"] == 1
    assert data["min_length"] == 4
    assert data["scan_capped"] is False
    assert data["strings"] == [
        {
            "string": "https://x.test/v1",
            "segment": 0,
            "segment_offset": off1,
            "offset": base + off1,
        },
        {"string": "short", "segment": 0, "segment_offset": off2, "offset": base + off2},
        {
            "string": "AUTHKEY=abcdef",
            "segment": 0,
            "segment_offset": off3,
            "offset": base + off3,
        },
    ]
    assert data["total"] == 3
    assert data["count"] == 3
    assert data["has_more"] is False


def test_passive_segment_has_no_memory_offset(tmp_path: Path) -> None:
    """A passive segment is not placed in memory, so offset is null."""
    data = _strings(tmp_path, _module(_data_section(_data_passive(b"passive-string-9449"))))
    assert data["strings"] == [
        {
            "string": "passive-string-9449",
            "segment": 0,
            "segment_offset": 0,
            "offset": None,
        }
    ]


def test_global_get_offset_is_unknown(tmp_path: Path) -> None:
    """An active segment based on an imported global has no static offset."""
    # flags 0, const-expr: global.get 0 ; end, then the bytes vector.
    segment = _uleb(0) + b"\x23" + _uleb(0) + b"\x0b" + _vec_bytes(b"based-on-global")
    data = _strings(tmp_path, _module(_data_section(segment)))
    assert data["strings"][0]["offset"] is None
    assert data["strings"][0]["segment_offset"] == 0


def test_multiple_segments_are_indexed(tmp_path: Path) -> None:
    """Each segment keeps its own index and its own memory base."""
    data = _strings(
        tmp_path,
        _module(
            _data_section(
                _data_active(0, b"first-segment"),
                _data_active_mem(0, 0x2000, b"second-segment"),
            )
        ),
    )
    assert data["data_segments"] == 2
    by_seg = {s["segment"]: s for s in data["strings"]}
    assert by_seg[0]["string"] == "first-segment"
    assert by_seg[0]["offset"] == 0
    assert by_seg[1]["string"] == "second-segment"
    assert by_seg[1]["offset"] == 0x2000


def test_min_length_filters_short_runs(tmp_path: Path) -> None:
    """A higher min_length drops the shorter runs."""
    blob = b"ok\x00longer-string\x00hi\x00another-long-one"
    data = _strings(
        tmp_path, _module(_data_section(_data_active(0, blob))), min_length=8
    )
    values = [s["string"] for s in data["strings"]]
    assert values == ["longer-string", "another-long-one"]
    assert data["min_length"] == 8


def test_no_data_section_is_empty_not_an_error(tmp_path: Path) -> None:
    data = _strings(tmp_path, _module(_section(1, _uleb(0))))  # a type section, no data
    assert data["strings"] == []
    assert data["data_segments"] == 0
    assert data["total"] == 0
    assert data["scanned_bytes"] == 0


def test_long_run_is_cut_and_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_STRING_LEN", 4)
    data = _strings(tmp_path, _module(_data_section(_data_active(0, b"abcdefghij"))))
    assert data["strings"][0]["string"] == "abcd"
    assert data["strings"][0]["value_truncated"] is True
    assert all(len(s["string"]) <= 4 for s in data["strings"])


def test_scan_cap_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_STRINGS_SCAN", 2)
    blob = b"aaaa\x00bbbb\x00cccc\x00dddd"
    data = _strings(tmp_path, _module(_data_section(_data_active(0, blob))))
    assert data["total"] == 2
    assert data["scan_capped"] is True


def test_paging_over_the_collected_strings(tmp_path: Path) -> None:
    blob = b"str0aaa\x00str1bbb\x00str2ccc\x00str3ddd\x00str4eee"
    module = _module(_data_section(_data_active(0, blob)))
    first = _strings(tmp_path, module, limit=2)
    assert first["count"] == 2
    assert first["total"] == 5
    assert first["has_more"] is True
    last = _strings(tmp_path, module, offset=4, limit=2)
    assert last["count"] == 1
    assert last["offset"] == 4
    assert last["has_more"] is False


def test_bad_magic_is_a_clean_backend_error(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        _strings(tmp_path, b"\x7fELF not a wasm module")
    assert excinfo.value.code == "backend_error"
    assert "WebAssembly" in excinfo.value.message


def test_unsupported_const_expr_is_a_clean_backend_error(tmp_path: Path) -> None:
    # flags 0 with an offset expr this reader does not model (0xd2 ref.func).
    segment = _uleb(0) + b"\xd2" + _uleb(0) + b"\x0b" + _vec_bytes(b"x")
    with pytest.raises(JsReError) as excinfo:
        _strings(tmp_path, _module(_data_section(segment)))
    assert excinfo.value.code == "backend_error"
    assert "malformed" in excinfo.value.message


def test_segment_bytes_overrun_is_a_clean_backend_error(tmp_path: Path) -> None:
    # A segment whose declared byte length runs past the section.
    segment = _uleb(0) + _i32_offset(0) + _uleb(200) + b"short"
    with pytest.raises(JsReError) as excinfo:
        _strings(tmp_path, _module(_data_section(segment)))
    assert excinfo.value.code == "backend_error"


def test_needs_no_wabt(tmp_path: Path) -> None:
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    client._decompile = None
    assert client.available is False
    data = client.strings(_write(tmp_path, _module(_data_section(_data_active(0, b"nowabt")))))
    assert data["strings"][0]["string"] == "nowabt"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().strings(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_docstring_names_the_fields() -> None:
    doc = WasmClient.strings.__doc__ or ""
    for token in ("strings", "offset"):
        assert token in doc, token
