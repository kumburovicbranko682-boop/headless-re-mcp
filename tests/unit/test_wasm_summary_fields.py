"""Tests for WasmClient.summary, the structured wasm import/export reader.

These build tiny modules by hand so the parser is exercised without wabt: the
whole point of wasm.summary is that it reads the binary directly, so every test
here runs on a box with no wabt installed.
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


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + (1).to_bytes(4, "little") + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _summary(tmp_path: Path, data: bytes) -> dict:
    return WasmClient().summary(_write(tmp_path, data))


def test_parses_imports_exports_and_counts(tmp_path: Path) -> None:
    type_sec = _section(1, _uleb(1) + b"\x60\x00\x00")  # 1 type: () -> ()
    import_sec = _section(
        2,
        _uleb(2)
        + _name("env") + _name("log") + b"\x00" + _uleb(0)  # func import, type 0
        + _name("env") + _name("mem") + b"\x02" + b"\x00" + _uleb(1),  # memory import
    )
    export_sec = _section(7, _uleb(1) + _name("run") + b"\x00" + _uleb(0))  # func export
    global_sec = _section(6, _uleb(1) + b"\x7f\x01\x41\x00\x0b")  # 1 mutable i32 global

    data = _summary(tmp_path, _module(type_sec, import_sec, export_sec, global_sec))

    assert data["module"] == "m.wasm"
    assert data["version"] == 1
    assert data["imports"] == [
        {"module": "env", "name": "log", "kind": "func", "type_index": 0},
        {"module": "env", "name": "mem", "kind": "memory"},
    ]
    assert data["exports"] == [{"name": "run", "kind": "func", "index": 0}]
    assert data["import_count"] == 2
    assert data["export_count"] == 1
    assert data["global_count"] == 1
    assert data["type_count"] == 1
    assert data["sections"] == {"type": 1, "import": 2, "export": 1, "global": 1}
    assert "imports_truncated" not in data
    assert "exports_truncated" not in data


def test_table_and_global_import_kinds_advance_correctly(tmp_path: Path) -> None:
    # A table import (elemtype + limits) then a global import (valtype + mut),
    # then an export -- the export only resolves if the two import descriptors
    # were consumed with exactly the right widths.
    import_sec = _section(
        2,
        _uleb(2)
        + _name("env") + _name("tbl") + b"\x01" + b"\x70" + b"\x00" + _uleb(1)  # table
        + _name("env") + _name("g") + b"\x03" + b"\x7f" + b"\x01",  # global i32 mutable
    )
    export_sec = _section(7, _uleb(1) + _name("ok") + b"\x03" + _uleb(0))  # global export

    data = _summary(tmp_path, _module(import_sec, export_sec))

    assert [i["kind"] for i in data["imports"]] == ["table", "global"]
    assert data["imports"][0]["name"] == "tbl"
    assert data["exports"] == [{"name": "ok", "kind": "global", "index": 0}]


def test_empty_module_has_no_imports_or_exports(tmp_path: Path) -> None:
    data = _summary(tmp_path, _module())
    assert data["imports"] == []
    assert data["exports"] == []
    assert data["import_count"] == 0
    assert data["export_count"] == 0
    assert data["sections"] == {}


def test_export_list_is_capped_with_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_ITEMS", 2)
    exports = b"".join(_name(f"e{i}") + b"\x00" + _uleb(i) for i in range(3))
    export_sec = _section(7, _uleb(3) + exports)

    data = _summary(tmp_path, _module(export_sec))

    assert len(data["exports"]) == 2
    assert data["exports_truncated"] is True
    # The declared count stays the real total, so the truncation is honest.
    assert data["export_count"] == 3


def test_bad_magic_is_a_clean_backend_error(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        _summary(tmp_path, b"\x7fELF not a wasm module at all")
    assert excinfo.value.code == "backend_error"
    assert "WebAssembly" in excinfo.value.message


def test_section_overrun_is_a_clean_backend_error(tmp_path: Path) -> None:
    # A section that declares more bytes than the module actually holds.
    overrun = b"\x01" + _uleb(200) + b"\x00\x00"
    with pytest.raises(JsReError) as excinfo:
        _summary(tmp_path, _module(overrun))
    assert excinfo.value.code == "backend_error"
    assert "malformed" in excinfo.value.message


def test_truncated_name_is_a_clean_backend_error(tmp_path: Path) -> None:
    # Export section claims one export whose name length runs past the section.
    export_sec = _section(7, _uleb(1) + _uleb(50) + b"short")
    with pytest.raises(JsReError) as excinfo:
        _summary(tmp_path, _module(export_sec))
    assert excinfo.value.code == "backend_error"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().summary(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_summary_needs_no_wabt(tmp_path: Path) -> None:
    # Force the wabt tools absent: summary must still parse, since it reads bytes.
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    client._decompile = None
    assert client.available is False
    data = client.summary(_write(tmp_path, _module()))
    assert data["version"] == 1


def test_docstring_names_the_fields() -> None:
    doc = WasmClient.summary.__doc__ or ""
    for token in ("imports", "exports"):
        assert token in doc, token
