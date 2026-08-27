"""Unit tests for wasm.functions (pure-Python type/import/function cross-ref).

The parser is exercised against hand-crafted .wasm binaries carrying type,
import, function and "name" sections, so the signature resolution, the
imported-first index space, the name-section join, and the truncated/missing
degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_functions

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"
_VT = {
    "i32": 0x7F,
    "i64": 0x7E,
    "f32": 0x7D,
    "f64": 0x7C,
    "v128": 0x7B,
    "funcref": 0x70,
    "externref": 0x6F,
}


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


def _name(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _uleb(len(encoded)) + encoded


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _functype(params: list[str], results: list[str]) -> bytes:
    return (
        b"\x60"
        + _uleb(len(params))
        + bytes(_VT[p] for p in params)
        + _uleb(len(results))
        + bytes(_VT[r] for r in results)
    )


def _type_section(*fts: bytes) -> bytes:
    return _section(1, _uleb(len(fts)) + b"".join(fts))


def _func_import(module: str, field: str, typeidx: int) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _mem_import(module: str, field: str, minimum: int = 1) -> bytes:
    return _name(module) + _name(field) + b"\x02" + b"\x00" + _uleb(minimum)


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _function_section(*typeidxs: int) -> bytes:
    return _section(3, _uleb(len(typeidxs)) + b"".join(_uleb(t) for t in typeidxs))


def _namemap(pairs: list[tuple[int, str]]) -> bytes:
    out = _uleb(len(pairs))
    for idx, name in pairs:
        out += _uleb(idx) + _name(name)
    return out


def _name_section(pairs: list[tuple[int, str]]) -> bytes:
    mm = _namemap(pairs)
    func_sub = bytes([1]) + _uleb(len(mm)) + mm
    body = _name("name") + func_sub
    return bytes([0]) + _uleb(len(body)) + body


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_functions_local_signatures(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _type_section(_functype(["i32", "i32"], ["i32"]), _functype([], [])),
            _function_section(0, 1, 0),
        ),
    )

    payload = parse_wasm_functions(src)

    assert payload["imported_count"] == 0
    assert payload["total"] == 3
    assert payload["functions"] == [
        {
            "index": 0,
            "kind": "local",
            "type_index": 0,
            "params": ["i32", "i32"],
            "results": ["i32"],
        },
        {
            "index": 1,
            "kind": "local",
            "type_index": 1,
            "params": [],
            "results": [],
        },
        {
            "index": 2,
            "kind": "local",
            "type_index": 0,
            "params": ["i32", "i32"],
            "results": ["i32"],
        },
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_functions_imports_come_first(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _type_section(_functype([], []), _functype(["i32"], [])),
            # A memory import (skipped) precedes the func import; only funcs
            # occupy the function index space.
            _import_section(
                _mem_import("env", "memory", 256), _func_import("env", "log", 1)
            ),
            _function_section(0),
        ),
    )

    payload = parse_wasm_functions(src)

    assert payload["imported_count"] == 1
    assert payload["total"] == 2
    assert payload["functions"][0] == {
        "index": 0,
        "kind": "import",
        "module": "env",
        "name": "log",
        "type_index": 1,
        "params": ["i32"],
        "results": [],
    }
    assert payload["functions"][1] == {
        "index": 1,
        "kind": "local",
        "type_index": 0,
        "params": [],
        "results": [],
    }


def test_wasm_functions_joins_name_section_for_locals(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _type_section(_functype([], [])),
            _import_section(_func_import("env", "log", 0)),
            _function_section(0),
            _name_section([(1, "main")]),  # names the local at function index 1
        ),
    )

    payload = parse_wasm_functions(src)

    assert payload["functions"][0]["name"] == "log"  # from the import pair
    assert payload["functions"][1]["name"] == "main"  # from the name section


def test_wasm_functions_valtype_names(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _type_section(_functype(["i64", "f32"], ["f64", "v128"])),
            _function_section(0),
        ),
    )

    row = parse_wasm_functions(src)["functions"][0]

    assert row["params"] == ["i64", "f32"]
    assert row["results"] == ["f64", "v128"]


def test_wasm_functions_missing_type_section_leaves_sig_empty(
    tmp_path: Path,
) -> None:
    src = _write(tmp_path, _module(_function_section(0, 5)))

    payload = parse_wasm_functions(src)

    assert payload["truncated"] is False
    assert payload["functions"] == [
        {"index": 0, "kind": "local", "type_index": 0, "params": [], "results": []},
        {"index": 1, "kind": "local", "type_index": 5, "params": [], "results": []},
    ]


def test_wasm_functions_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_functions(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_functions_truncated_type_section_is_marked(tmp_path: Path) -> None:
    # The type section claims 2 functypes but supplies only 1.
    ts = _section(1, _uleb(2) + _functype([], []))
    src = _write(tmp_path, _module(ts, _function_section(0, 1)))

    payload = parse_wasm_functions(src)

    assert payload["truncated"] is True
    assert payload["total"] == 2
    # type 0 resolved to (); type 1 unresolved -> empty, index still reported.
    assert payload["functions"][0]["params"] == []
    assert payload["functions"][1]["type_index"] == 1
    assert payload["functions"][1]["params"] == []


def test_wasm_functions_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _type_section(_functype([], [])),
            _function_section(*([0] * 5)),
        ),
    )

    payload = parse_wasm_functions(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["functions"]] == [2, 3]


def test_wasm_functions_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_FUNCTIONS_COLLECT", 3
    )
    src = _write(
        tmp_path,
        _module(_type_section(_functype([], [])), _function_section(*([0] * 10))),
    )

    payload = parse_wasm_functions(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_functions_clamps_oversized_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_FUNCTIONS_PAGE", 2
    )
    src = _write(
        tmp_path,
        _module(_type_section(_functype([], [])), _function_section(*([0] * 5))),
    )

    payload = parse_wasm_functions(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_functions_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_functions(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_functions_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(
        tmp_path,
        _module(_type_section(_functype([], [])), _function_section(0)),
    )

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_functions(src)
    assert excinfo.value.code == "too_large"


def test_wasm_functions_docstring_names_shape() -> None:
    doc = parse_wasm_functions.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc
