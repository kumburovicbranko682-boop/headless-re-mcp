"""wasm.summary reads a module's imports/exports/sections in-process, no wabt.

wasm.wat/wasm.info shell out to wabt and return text to grep, and are
unavailable when wabt is absent. wasm.summary parses the binary sections
directly. These build minimal but real module bytes (LEB128 vectors, named
imports/exports, a start section, a custom section, and an opaque section that
must be skipped by size) and cover the structured read, the caps/truncation
flags, the bad-input refusals, and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import WasmParseError, summarize
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

_HEADER = b"\x00asm\x01\x00\x00\x00"


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


def _section(sec_id: int, body: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(body)) + body


def _limits(minimum: int, maximum: int | None = None) -> bytes:
    if maximum is None:
        return bytes([0x00]) + _uleb(minimum)
    return bytes([0x01]) + _uleb(minimum) + _uleb(maximum)


def _import(module: str, field: str, kind: int, desc: bytes) -> bytes:
    return _name(module) + _name(field) + bytes([kind]) + desc


def _export(name: str, kind: int, index: int) -> bytes:
    return _name(name) + bytes([kind]) + _uleb(index)


def _sample_module() -> bytes:
    imports = [
        _import("env", "memory", 2, _limits(1)),
        _import("env", "abort", 0, _uleb(0)),
        _import("wasi_snapshot_preview1", "fd_write", 0, _uleb(1)),
    ]
    import_body = _uleb(len(imports)) + b"".join(imports)
    exports = [_export("memory", 2, 0), _export("main", 0, 3)]
    export_body = _uleb(len(exports)) + b"".join(exports)
    custom_body = _name("name") + b"\x00\x01\x02"
    return (
        _HEADER
        + _section(1, _uleb(0))  # empty type section, skipped by size
        + _section(2, import_body)
        + _section(10, b"\xde\xad\xbe\xef")  # opaque "code" section, skipped
        + _section(7, export_body)
        + _section(8, _uleb(3))  # start function index 3
        + _section(0, custom_body)  # custom section carrying a name
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


def test_summarize_reads_imports_exports_sections_and_start() -> None:
    result = summarize(_sample_module())
    assert result["version"] == 1
    assert result["imports_total"] == 3
    assert result["imports_count"] == 3
    assert result["imports_truncated"] is False
    by_name = {(row["module"], row["name"]): row for row in result["imports"]}
    assert by_name[("env", "abort")]["kind"] == "func"
    assert by_name[("env", "abort")]["type_index"] == 0
    assert by_name[("wasi_snapshot_preview1", "fd_write")]["type_index"] == 1
    assert by_name[("env", "memory")]["kind"] == "memory"
    exports = {row["name"]: row for row in result["exports"]}
    assert result["exports_total"] == 2
    assert exports["memory"] == {"name": "memory", "kind": "memory", "index": 0}
    assert exports["main"] == {"name": "main", "kind": "func", "index": 3}
    assert result["start_function"] == 3
    sections = {row["name"]: row for row in result["sections"]}
    # The opaque section was listed from its framing and skipped, not decoded.
    assert sections["code"]["size"] == 4
    assert sections["custom"]["custom_name"] == "name"
    assert {"import", "export", "start", "type"} <= set(sections)


def test_summarize_caps_and_marks_truncation() -> None:
    result = summarize(_sample_module(), max_imports=1)
    assert result["imports_count"] == 1
    assert result["imports_total"] == 3
    assert result["imports_truncated"] is True
    # exports untouched by the import cap.
    assert result["exports_truncated"] is False


def test_summarize_rejects_bad_magic_and_short_input() -> None:
    with pytest.raises(WasmParseError):
        summarize(b"this is not wasm at all")
    with pytest.raises(WasmParseError):
        summarize(b"\x00asm")  # header only, under 8 bytes


def test_summarize_rejects_section_that_overruns_module() -> None:
    truncated = _HEADER + bytes([2]) + _uleb(100)  # import section claims 100 bytes
    with pytest.raises(WasmParseError):
        summarize(truncated)


def test_summarize_bounds_a_runaway_leb128() -> None:
    runaway = _HEADER + bytes([2]) + b"\x80" * 12  # size field never terminates
    with pytest.raises(WasmParseError):
        summarize(runaway)


def test_client_summary_reads_a_file_without_wabt(tmp_path: Path) -> None:
    module = tmp_path / "mod.wasm"
    module.write_bytes(_sample_module())
    # No wabt configured; summary must still work (pure-Python parse).
    result = WasmClient(None).summary(module)
    assert result["imports_total"] == 3
    assert result["exports_total"] == 2


def test_client_summary_refuses_non_wasm_as_invalid_params(tmp_path: Path) -> None:
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b"definitely not a wasm module")
    with pytest.raises(jsre_client.JsReError) as info:
        WasmClient(None).summary(bad)
    assert info.value.code == "invalid_params"


def test_client_summary_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(jsre_client.JsReError) as info:
        WasmClient(None).summary(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_client_summary_refuses_oversized_input(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_INPUT_BYTES", 64)
    big = tmp_path / "big.wasm"
    big.write_bytes(_sample_module() + b"\x00" * 128)
    with pytest.raises(jsre_client.JsReError) as info:
        WasmClient(None).summary(big)
    assert info.value.code == "too_large"


def test_wasm_summary_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("wasm.summary").split())
    assert "without wabt" in doc
    assert "imports_total" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "wasm.summary" in _READ_ONLY_NAMES
