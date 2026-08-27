"""Unit tests for wasm.imports (pure-Python, wabt-free import-section parser).

The parser is exercised against hand-crafted .wasm binaries so the LEB128
decoding, per-kind descriptor skipping, binary-order preservation, and the
malformed/truncated degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_imports

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


def _name(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _uleb(len(encoded)) + encoded


def _imp_func(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _imp_table(module: str, field: str) -> bytes:
    # reftype funcref (0x70), limits flag 0x00, min 1
    return _name(module) + _name(field) + b"\x01" + b"\x70" + b"\x00" + _uleb(1)


def _imp_memory(module: str, field: str, minimum: int, maximum: int | None = None) -> bytes:
    if maximum is None:
        desc = b"\x02" + b"\x00" + _uleb(minimum)
    else:
        desc = b"\x02" + b"\x01" + _uleb(minimum) + _uleb(maximum)
    return _name(module) + _name(field) + desc


def _imp_global(module: str, field: str) -> bytes:
    # valtype i32 (0x7f), mutability 0
    return _name(module) + _name(field) + b"\x03" + b"\x7f" + b"\x00"


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _module(*imports: bytes) -> bytes:
    body = _uleb(len(imports)) + b"".join(imports)
    return _PREAMBLE + _section(2, body)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_imports_all_kinds_in_order(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _imp_func("env", "log", 3),
            _imp_memory("env", "memory", 256, 512),
            _imp_table("env", "tbl"),
            _imp_global("env", "STACK"),
        ),
    )

    payload = parse_wasm_imports(src)

    assert payload["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "env", "name": "memory", "kind": "memory"},
        {"module": "env", "name": "tbl", "kind": "table"},
        {"module": "env", "name": "STACK", "kind": "global"},
    ]
    assert payload["count"] == 4
    assert payload["total"] == 4
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False


def test_wasm_imports_memory_without_max(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_imp_memory("env", "memory", 1)))

    payload = parse_wasm_imports(src)

    assert payload["imports"] == [
        {"module": "env", "name": "memory", "kind": "memory"}
    ]
    assert payload["truncated"] is False


def test_wasm_imports_empty_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module())

    payload = parse_wasm_imports(src)

    assert payload["imports"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_wasm_imports_no_import_section(tmp_path: Path) -> None:
    # A bare preamble plus an unrelated (type) section, id 1.
    src = _write(tmp_path, _PREAMBLE + _section(1, _uleb(0)))

    payload = parse_wasm_imports(src)

    assert payload["imports"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_wasm_imports_skips_custom_section_before_imports(tmp_path: Path) -> None:
    custom = _section(0, _name("producers") + b"\x01\x02\x03")
    body = _uleb(1) + _imp_func("wasi_snapshot_preview1", "fd_write", 0)
    src = _write(tmp_path, _PREAMBLE + custom + _section(2, body))

    payload = parse_wasm_imports(src)

    assert payload["imports"] == [
        {"module": "wasi_snapshot_preview1", "name": "fd_write", "kind": "func"}
    ]


def test_wasm_imports_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"GIF89a not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_imports(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_imports_truncated_count_is_marked(tmp_path: Path) -> None:
    # Declare 3 imports but supply only 1; the parse stops and flags truncated.
    body = _uleb(3) + _imp_func("env", "a", 0)
    src = _write(tmp_path, _PREAMBLE + _section(2, body))

    payload = parse_wasm_imports(src)

    assert payload["imports"] == [{"module": "env", "name": "a", "kind": "func"}]
    assert payload["truncated"] is True


def test_wasm_imports_paginates(tmp_path: Path) -> None:
    imports = tuple(_imp_func("env", f"f{i:03d}", 0) for i in range(5))
    src = _write(tmp_path, _module(*imports))

    payload = parse_wasm_imports(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [row["name"] for row in payload["imports"]] == ["f002", "f003"]


def test_wasm_imports_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_IMPORTS_COLLECT", 3
    )
    imports = tuple(_imp_func("env", f"f{i:03d}", 0) for i in range(10))
    src = _write(tmp_path, _module(*imports))

    payload = parse_wasm_imports(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_imports_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_IMPORTS_PAGE", 2
    )
    imports = tuple(_imp_func("env", f"f{i:03d}", 0) for i in range(5))
    src = _write(tmp_path, _module(*imports))

    payload = parse_wasm_imports(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_imports_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_imports(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_imports_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_imp_func("env", "log", 0)))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_imports(src)
    assert excinfo.value.code == "too_large"


def test_wasm_imports_docstring_names_shape() -> None:
    doc = parse_wasm_imports.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc
