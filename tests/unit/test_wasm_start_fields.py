"""Unit tests for wasm.start (pure-Python start-section / auto-run reporter).

The reporter is exercised against hand-crafted modules whose start section
points at a module-defined function, at an imported function (the unusual
case), and is absent, plus a truncated section, so the import/local
classification and the degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_start

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


def _start_section(func_index: int) -> bytes:
    return _section(8, _uleb(func_index))


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_start_local_function(tmp_path: Path) -> None:
    # One imported func (index 0); the start function is local (index 1).
    src = _write(
        tmp_path,
        _module(_import_section(_func_import("env", "log")), _start_section(1)),
    )

    payload = parse_wasm_start(src)

    assert payload["has_start_section"] is True
    assert payload["start_function"] == 1
    assert payload["kind"] == "local"
    assert payload["imported_count"] == 1
    assert payload["truncated"] is False


def test_wasm_start_no_imports_is_local(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_start_section(0)))

    payload = parse_wasm_start(src)

    assert payload["start_function"] == 0
    assert payload["kind"] == "local"
    assert payload["imported_count"] == 0


def test_wasm_start_imported_function_is_flagged(tmp_path: Path) -> None:
    # Two imported funcs (indices 0,1); the start function is imported (0).
    src = _write(
        tmp_path,
        _module(
            _import_section(
                _func_import("env", "boot"), _func_import("env", "log")
            ),
            _start_section(0),
        ),
    )

    payload = parse_wasm_start(src)

    assert payload["start_function"] == 0
    assert payload["kind"] == "import"
    assert payload["imported_count"] == 2


def test_wasm_start_no_start_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_start(src)

    assert payload["has_start_section"] is False
    assert payload["start_function"] is None
    assert payload["kind"] is None


def test_wasm_start_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_start(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_start_truncated_section_is_marked(tmp_path: Path) -> None:
    # The start section declares a size but carries no index bytes.
    src = _write(tmp_path, _module(_section(8, b"")))

    payload = parse_wasm_start(src)

    assert payload["has_start_section"] is True
    assert payload["start_function"] is None
    assert payload["kind"] is None
    assert payload["truncated"] is True


def test_wasm_start_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_start(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_start_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_start_section(0)))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_start(src)
    assert excinfo.value.code == "too_large"


def test_wasm_start_docstring_names_shape() -> None:
    doc = parse_wasm_start.__doc__ or ""
    assert "wabt-free" in doc
    assert "start function" in doc
    assert "truncated" in doc
