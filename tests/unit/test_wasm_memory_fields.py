"""Unit tests for wasm.memory (pure-Python linear-memory table parser).

The parser is exercised against hand-crafted .wasm binaries whose memory and
import sections carry min-only, min+max, shared (threads) and memory64 limits
records, so the limits flag decoding, the import/local index-space join, and
the truncated/missing degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_memory

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"


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


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _limits(flag: int, minimum: int, maximum: int | None = None) -> bytes:
    out = bytes([flag]) + _uleb(minimum)
    if maximum is not None:
        out += _uleb(maximum)
    return out


def _memory_section(*mems: bytes) -> bytes:
    return _section(5, _uleb(len(mems)) + b"".join(mems))


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _mem_import(module: str, field: str, limits: bytes) -> bytes:
    return _name(module) + _name(field) + b"\x02" + limits


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_memory_local_min_max(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_memory_section(_limits(0x01, 2, 10))))

    payload = parse_wasm_memory(src)

    assert payload["total"] == 1
    assert payload["imported_count"] == 0
    assert payload["memories"] == [
        {
            "index": 0,
            "kind": "local",
            "min": 2,
            "max": 10,
            "shared": False,
            "index_type": "i32",
        }
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_memory_min_only_has_null_max(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_memory_section(_limits(0x00, 1))))

    row = parse_wasm_memory(src)["memories"][0]

    assert row["min"] == 1
    assert row["max"] is None


def test_wasm_memory_shared_flag(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_memory_section(_limits(0x03, 1, 100))))

    row = parse_wasm_memory(src)["memories"][0]

    assert row["shared"] is True
    assert row["min"] == 1
    assert row["max"] == 100
    assert row["index_type"] == "i32"


def test_wasm_memory_memory64_flag(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_memory_section(_limits(0x04, 1))))

    row = parse_wasm_memory(src)["memories"][0]

    assert row["index_type"] == "i64"
    assert row["shared"] is False
    assert row["max"] is None


def test_wasm_memory_imports_come_first(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _import_section(
                _func_import("env", "log"),  # non-memory import is skipped
                _mem_import("env", "memory", _limits(0x01, 256, 512)),
            ),
            _memory_section(_limits(0x00, 4)),
        ),
    )

    payload = parse_wasm_memory(src)

    assert payload["total"] == 2
    assert payload["imported_count"] == 1
    assert payload["memories"][0] == {
        "index": 0,
        "kind": "import",
        "module": "env",
        "name": "memory",
        "min": 256,
        "max": 512,
        "shared": False,
        "index_type": "i32",
    }
    assert payload["memories"][1] == {
        "index": 1,
        "kind": "local",
        "min": 4,
        "max": None,
        "shared": False,
        "index_type": "i32",
    }


def test_wasm_memory_no_memory(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_memory(src)

    assert payload["memories"] == []
    assert payload["total"] == 0
    assert payload["imported_count"] == 0


def test_wasm_memory_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_memory(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_memory_truncated_section_is_marked(tmp_path: Path) -> None:
    # The memory section claims two memories but only one limits record follows.
    body = _uleb(2) + _limits(0x00, 1)
    src = _write(tmp_path, _module(_section(5, body)))

    payload = parse_wasm_memory(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["memories"][0]["min"] == 1


def test_wasm_memory_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_memory_section(*[_limits(0x00, i + 1) for i in range(5)])),
    )

    payload = parse_wasm_memory(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["memories"]] == [2, 3]


def test_wasm_memory_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_MEMORIES_COLLECT", 3
    )
    src = _write(
        tmp_path,
        _module(_memory_section(*[_limits(0x00, i + 1) for i in range(10)])),
    )

    payload = parse_wasm_memory(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_memory_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_MEMORIES_PAGE", 2
    )
    src = _write(
        tmp_path,
        _module(_memory_section(*[_limits(0x00, i + 1) for i in range(5)])),
    )

    payload = parse_wasm_memory(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_memory_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_memory(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_memory_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_memory_section(_limits(0x00, 1))))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_memory(src)
    assert excinfo.value.code == "too_large"


def test_wasm_memory_docstring_names_shape() -> None:
    doc = parse_wasm_memory.__doc__ or ""
    assert "wabt-free" in doc
    assert "shared" in doc
    assert "truncated" in doc
