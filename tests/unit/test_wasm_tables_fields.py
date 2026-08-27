"""Unit tests for wasm.tables (pure-Python table/indirect-call-surface parser).

The parser is exercised against hand-crafted .wasm binaries whose table and
import sections carry funcref, externref and unknown-reftype tabletypes with
min-only and min+max limits, so the reftype naming, the limits reuse, the
import/local index-space join, and the truncated degradation are all really
executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_tables

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


def _tabletype(reftype: int, limits: bytes) -> bytes:
    return bytes([reftype]) + limits


def _table_section(*tables: bytes) -> bytes:
    return _section(4, _uleb(len(tables)) + b"".join(tables))


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _table_import(module: str, field: str, tabletype: bytes) -> bytes:
    return _name(module) + _name(field) + b"\x01" + tabletype


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_tables_local_funcref(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_table_section(_tabletype(0x70, _limits(0x01, 16, 64)))),
    )

    payload = parse_wasm_tables(src)

    assert payload["total"] == 1
    assert payload["imported_count"] == 0
    assert payload["tables"] == [
        {
            "index": 0,
            "kind": "local",
            "element_type": "funcref",
            "min": 16,
            "max": 64,
        }
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_tables_externref_min_only(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_table_section(_tabletype(0x6F, _limits(0x00, 2)))),
    )

    row = parse_wasm_tables(src)["tables"][0]

    assert row["element_type"] == "externref"
    assert row["min"] == 2
    assert row["max"] is None


def test_wasm_tables_unknown_reftype_renders_hex(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(_table_section(_tabletype(0x63, _limits(0x00, 1)))),
    )

    row = parse_wasm_tables(src)["tables"][0]

    assert row["element_type"] == "0x63"


def test_wasm_tables_imports_come_first(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _import_section(
                _func_import("env", "log"),  # non-table import is skipped
                _table_import(
                    "env",
                    "__indirect_function_table",
                    _tabletype(0x70, _limits(0x01, 128, 128)),
                ),
            ),
            _table_section(_tabletype(0x6F, _limits(0x00, 1))),
        ),
    )

    payload = parse_wasm_tables(src)

    assert payload["total"] == 2
    assert payload["imported_count"] == 1
    assert payload["tables"][0] == {
        "index": 0,
        "kind": "import",
        "module": "env",
        "name": "__indirect_function_table",
        "element_type": "funcref",
        "min": 128,
        "max": 128,
    }
    assert payload["tables"][1] == {
        "index": 1,
        "kind": "local",
        "element_type": "externref",
        "min": 1,
        "max": None,
    }


def test_wasm_tables_no_tables(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_tables(src)

    assert payload["tables"] == []
    assert payload["total"] == 0
    assert payload["imported_count"] == 0


def test_wasm_tables_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_tables(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_tables_truncated_section_is_marked(tmp_path: Path) -> None:
    # The table section claims two tables but only one tabletype follows.
    body = _uleb(2) + _tabletype(0x70, _limits(0x00, 1))
    src = _write(tmp_path, _module(_section(4, body)))

    payload = parse_wasm_tables(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["tables"][0]["element_type"] == "funcref"


def test_wasm_tables_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _table_section(
                *[_tabletype(0x70, _limits(0x00, i + 1)) for i in range(5)]
            )
        ),
    )

    payload = parse_wasm_tables(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["tables"]] == [2, 3]


def test_wasm_tables_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_TABLES_COLLECT", 3
    )
    src = _write(
        tmp_path,
        _module(
            _table_section(
                *[_tabletype(0x70, _limits(0x00, i + 1)) for i in range(10)]
            )
        ),
    )

    payload = parse_wasm_tables(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_tables_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_TABLES_PAGE", 2
    )
    src = _write(
        tmp_path,
        _module(
            _table_section(
                *[_tabletype(0x70, _limits(0x00, i + 1)) for i in range(5)]
            )
        ),
    )

    payload = parse_wasm_tables(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_tables_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_tables(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_tables_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(
        tmp_path, _module(_table_section(_tabletype(0x70, _limits(0x00, 1))))
    )

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_tables(src)
    assert excinfo.value.code == "too_large"


def test_wasm_tables_docstring_names_shape() -> None:
    doc = parse_wasm_tables.__doc__ or ""
    assert "wabt-free" in doc
    assert "call_indirect" in doc
    assert "truncated" in doc
