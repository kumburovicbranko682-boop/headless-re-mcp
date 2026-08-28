"""wasm.summary parses a module's imports/exports/counts in-process (no wabt)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, WasmClient
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


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _build_module() -> bytes:
    # One () -> () function type.
    type_body = _uleb(1) + b"\x60" + _uleb(0) + _uleb(0)
    # Three imports: two host functions and a linear memory.
    import_body = _uleb(3)
    import_body += _name("env") + _name("log") + b"\x00" + _uleb(0)
    import_body += _name("wasi_snapshot_preview1") + _name("fd_write") + b"\x00" + _uleb(0)
    import_body += _name("env") + _name("memory") + b"\x02" + b"\x00" + _uleb(1)
    # One defined function of type 0.
    func_body = _uleb(1) + _uleb(0)
    # One memory (min 1).
    mem_body = _uleb(1) + b"\x00" + _uleb(1)
    # Two globals (only the leading count is read; entries kept realistic).
    global_body = _uleb(2) + b"\x7f\x00\x41\x00\x0b" + b"\x7f\x00\x41\x00\x0b"
    # Two exports: a function and the memory.
    export_body = _uleb(2)
    export_body += _name("add") + b"\x00" + _uleb(1)
    export_body += _name("memory") + b"\x02" + _uleb(0)
    # A start function.
    start_body = _uleb(1)
    return (
        b"\x00asm"
        + b"\x01\x00\x00\x00"
        + _section(1, type_body)
        + _section(2, import_body)
        + _section(3, func_body)
        + _section(5, mem_body)
        + _section(6, global_body)
        + _section(7, export_body)
        + _section(8, start_body)
    )


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


def test_wasm_summary_extracts_imports_exports_and_counts(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_build_module())
    data = WasmClient().summary(module)
    assert data["version"] == 1
    assert data["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "wasi_snapshot_preview1", "name": "fd_write", "kind": "func"},
        {"module": "env", "name": "memory", "kind": "memory"},
    ]
    assert data["exports"] == [
        {"name": "add", "kind": "func", "index": 1},
        {"name": "memory", "kind": "memory", "index": 0},
    ]
    assert data["imported"] == {"func": 2, "table": 0, "memory": 1, "global": 0}
    assert data["counts"]["types"] == 1
    assert data["counts"]["functions"] == 1
    assert data["counts"]["memories"] == 1
    assert data["counts"]["globals"] == 2
    assert data["counts"]["imports"] == 3
    assert data["counts"]["exports"] == 2
    assert data["import_count"] == 3
    assert data["export_count"] == 2
    assert data["has_start"] is True
    assert "truncated" not in data


def test_wasm_summary_needs_no_wabt(tmp_path: Path) -> None:
    """summary must not depend on wat2wasm/wasm-objdump being configured."""
    module = tmp_path / "m.wasm"
    module.write_bytes(_build_module())
    # A client with no wabt tools resolved still summarizes.
    client = WasmClient()
    client._wasm2wat = None  # type: ignore[assignment]
    client._objdump = None  # type: ignore[assignment]
    data = client.summary(module)
    assert data["import_count"] == 3


def test_wasm_summary_rejects_non_wasm(tmp_path: Path) -> None:
    junk = tmp_path / "not.wasm"
    junk.write_bytes(b"MZ\x00\x00not a module")
    with pytest.raises(JsReError) as excinfo:
        WasmClient().summary(junk)
    assert excinfo.value.code == "invalid_params"


def test_wasm_summary_flags_a_truncated_module(tmp_path: Path) -> None:
    """A section whose declared length overruns the file is best-effort: the
    parse stops and truncated is set rather than crashing."""
    good = _build_module()
    # Keep the header and the (valid) type section, then append an import
    # section that claims far more bytes than remain.
    header = b"\x00asm" + b"\x01\x00\x00\x00"
    type_body = _uleb(1) + b"\x60" + _uleb(0) + _uleb(0)
    broken = header + _section(1, type_body) + bytes([2]) + _uleb(9999) + b"\x01"
    module = tmp_path / "broken.wasm"
    module.write_bytes(broken)
    data = WasmClient().summary(module)
    assert data["truncated"] is True
    assert data["counts"]["types"] == 1
    assert data["imports"] == []
    assert good  # sanity that the good builder ran


def test_wasm_summary_docstring_names_imports_and_no_wabt() -> None:
    doc = _tool_docstring("wasm.summary")
    assert "imports" in doc
    assert "exports" in doc
    assert "kind" in doc
    assert "wabt" in doc
