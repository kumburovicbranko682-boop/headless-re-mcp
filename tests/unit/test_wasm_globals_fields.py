"""Unit tests for wasm.globals (pure-Python global/import cross-ref).

The parser is exercised against hand-crafted .wasm binaries carrying global and
import sections, so the globaltype read, the const-expression skip over each
initialiser, the imported-first index space, and the truncated/missing
degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_globals

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


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7  # Python arithmetic shift keeps the sign for negatives
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        if done:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _name(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _uleb(len(encoded)) + encoded


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _const_i32(n: int) -> bytes:
    # i32.const <sleb> end -- a minimal constant expression.
    return b"\x41" + _sleb(n) + b"\x0b"


def _local_global(vt: str, mut: int, init: bytes) -> bytes:
    return bytes([_VT[vt], mut]) + init


def _global_section(*globals_: bytes) -> bytes:
    return _section(6, _uleb(len(globals_)) + b"".join(globals_))


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _global_import(module: str, field: str, vt: str, mut: int) -> bytes:
    return _name(module) + _name(field) + b"\x03" + bytes([_VT[vt], mut])


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_globals_local_types_and_mutability(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _global_section(
                _local_global("i32", 0x01, _const_i32(0)),
                _local_global("i32", 0x00, _const_i32(16)),
            )
        ),
    )

    payload = parse_wasm_globals(src)

    assert payload["imported_count"] == 0
    assert payload["total"] == 2
    assert payload["globals"] == [
        {"index": 0, "kind": "local", "type": "i32", "mutable": True},
        {"index": 1, "kind": "local", "type": "i32", "mutable": False},
    ]
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_globals_imports_come_first(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            # A func import (skipped) precedes the global import; only globals
            # occupy the global index space.
            _import_section(
                _func_import("env", "log"),
                _global_import("env", "__stack_pointer", "i32", 0x01),
            ),
            _global_section(_local_global("i32", 0x00, _const_i32(0))),
        ),
    )

    payload = parse_wasm_globals(src)

    assert payload["imported_count"] == 1
    assert payload["total"] == 2
    assert payload["globals"][0] == {
        "index": 0,
        "kind": "import",
        "module": "env",
        "name": "__stack_pointer",
        "type": "i32",
        "mutable": True,
    }
    assert payload["globals"][1] == {
        "index": 1,
        "kind": "local",
        "type": "i32",
        "mutable": False,
    }


def test_wasm_globals_value_type_names(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _global_section(
                _local_global("i64", 0x00, _const_i32(0)),
                _local_global("f64", 0x01, _const_i32(0)),
            )
        ),
    )

    rows = parse_wasm_globals(src)["globals"]

    assert rows[0]["type"] == "i64"
    assert rows[0]["mutable"] is False
    assert rows[1]["type"] == "f64"
    assert rows[1]["mutable"] is True


def test_wasm_globals_skips_global_get_initialiser(tmp_path: Path) -> None:
    # An init of `global.get 0; end` must be stepped over cleanly.
    src = _write(
        tmp_path,
        _module(
            _import_section(_global_import("env", "base", "i32", 0x00)),
            _global_section(_local_global("i32", 0x00, b"\x23\x00\x0b")),
        ),
    )

    payload = parse_wasm_globals(src)

    assert payload["truncated"] is False
    assert payload["total"] == 2
    assert payload["globals"][1] == {
        "index": 1,
        "kind": "local",
        "type": "i32",
        "mutable": False,
    }


def test_wasm_globals_no_globals(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_globals(src)

    assert payload["globals"] == []
    assert payload["total"] == 0
    assert payload["imported_count"] == 0


def test_wasm_globals_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_globals(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_globals_unknown_init_opcode_is_marked(tmp_path: Path) -> None:
    # First global's init is valid; the second uses opcode 0xFE, outside the
    # constant-expression set, so the parse keeps the first and flags truncated.
    src = _write(
        tmp_path,
        _module(
            _global_section(
                _local_global("i32", 0x00, _const_i32(0)),
                bytes([_VT["i32"], 0x00]) + b"\xfe\x0b",
            )
        ),
    )

    payload = parse_wasm_globals(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["globals"][0]["index"] == 0


def test_wasm_globals_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _global_section(
                *[_local_global("i32", 0x00, _const_i32(i)) for i in range(5)]
            )
        ),
    )

    payload = parse_wasm_globals(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["globals"]] == [2, 3]


def test_wasm_globals_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_GLOBALS_COLLECT", 3
    )
    src = _write(
        tmp_path,
        _module(
            _global_section(
                *[_local_global("i32", 0x00, _const_i32(i)) for i in range(10)]
            )
        ),
    )

    payload = parse_wasm_globals(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_globals_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_GLOBALS_PAGE", 2
    )
    src = _write(
        tmp_path,
        _module(
            _global_section(
                *[_local_global("i32", 0x00, _const_i32(i)) for i in range(5)]
            )
        ),
    )

    payload = parse_wasm_globals(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_globals_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_globals(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_globals_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(
        tmp_path,
        _module(_global_section(_local_global("i32", 0x00, _const_i32(0)))),
    )

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_globals(src)
    assert excinfo.value.code == "too_large"


def test_wasm_globals_docstring_names_shape() -> None:
    doc = parse_wasm_globals.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc
