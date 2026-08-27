"""wasm.summary parses a module's section table straight from the bytes.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing) and assert the import/export/memory/count shape,
the 4096-item cut, and that hostile input is refused rather than crashed on.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, summarize_wasm_bytes
from headless_re_mcp.backends.jsre.wasm_summary import _MAX_ITEMS
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


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, content: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(content)) + content


def _module(*sections: bytes) -> bytes:
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


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


def test_wasm_summary_reads_the_interop_surface() -> None:
    """A module with an imported func, an imported memory, exports and a start.

    imports must name the host boundary (env.log / env.mem), exports the
    callable surface (run / memory), memory its page limits, and the counts must
    separate the imported function from the one defined in the module.
    """
    type_sec = _section(1, _vec([b"\x60\x00\x00"]))  # one () -> () type
    import_sec = _section(
        2,
        _vec(
            [
                _name("env") + _name("log") + b"\x00" + _uleb(0),  # func, type 0
                _name("env") + _name("mem") + b"\x02" + b"\x00" + _uleb(1),  # memory, min 1
            ]
        ),
    )
    func_sec = _section(3, _vec([_uleb(0)]))  # one defined function of type 0
    mem_sec = _section(5, _vec([b"\x01" + _uleb(2) + _uleb(16)]))  # min 2, max 16
    export_sec = _section(
        7,
        _vec(
            [
                _name("run") + b"\x00" + _uleb(1),  # func index 1
                _name("memory") + b"\x02" + _uleb(0),  # memory index 0
            ]
        ),
    )
    start_sec = _section(8, _uleb(1))
    custom_sec = _section(0, _name("name") + b"\x00")
    module = _module(
        type_sec, import_sec, func_sec, mem_sec, export_sec, start_sec, custom_sec
    )

    summary = summarize_wasm_bytes(module)
    assert summary["version"] == 1
    assert summary["imports"] == [
        {"module": "env", "name": "log", "kind": "func"},
        {"module": "env", "name": "mem", "kind": "memory"},
    ]
    assert summary["import_count"] == 2
    assert summary["exports"] == [
        {"name": "run", "kind": "func", "index": 1},
        {"name": "memory", "kind": "memory", "index": 0},
    ]
    assert summary["export_count"] == 2
    assert summary["memory"] == {"initial": 2, "maximum": 16}
    assert summary["has_start"] is True
    assert summary["custom_sections"] == ["name"]
    counts = summary["counts"]
    assert counts["types"] == 1
    assert counts["functions"] == 1
    assert counts["imported_functions"] == 1
    assert counts["memories"] == 1
    assert counts["tables"] == 0
    assert counts["globals"] == 0
    assert counts["data_segments"] == 0
    # A clean list carries no truncation flags.
    assert "imports_truncated" not in summary
    assert "exports_truncated" not in summary


def test_wasm_summary_reports_a_module_with_no_memory() -> None:
    module = _module(_section(1, _vec([b"\x60\x00\x00"])))
    summary = summarize_wasm_bytes(module)
    assert summary["memory"] is None
    assert summary["counts"]["memories"] == 0
    assert summary["imports"] == []
    assert summary["exports"] == []
    assert summary["has_start"] is False


def test_wasm_summary_caps_a_huge_export_list() -> None:
    exports = [_name(f"e{index}") + b"\x00" + _uleb(index) for index in range(_MAX_ITEMS + 5)]
    module = _module(_section(7, _vec(exports)))
    summary = summarize_wasm_bytes(module)
    assert summary["export_count"] == _MAX_ITEMS
    assert summary["exports_truncated"] is True
    assert summary["exports_total"] == _MAX_ITEMS + 5
    assert summary["exports_limit"] == _MAX_ITEMS
    # The kept slice is the head of the list, in order.
    assert summary["exports"][0] == {"name": "e0", "kind": "func", "index": 0}


def test_wasm_summary_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as caught:
        summarize_wasm_bytes(b"MZ\x90\x00this is a PE, not wasm")
    assert caught.value.code == "invalid_params"


def test_wasm_summary_rejects_a_truncated_section() -> None:
    # A section that claims 40 bytes but the module ends immediately: the body
    # slice is short, and reading the import vector must fail cleanly, not crash.
    truncated = _module(bytes([2]) + _uleb(40) + b"\x01\x03env")
    with pytest.raises(JsReError) as caught:
        summarize_wasm_bytes(truncated)
    assert caught.value.code == "invalid_params"


def test_wasm_summary_rejects_overlong_leb128() -> None:
    # A run of continuation bytes that never terminates must be refused, not
    # looped on: this is the classic decompression-bomb shape for LEB128.
    bomb = _module(bytes([1]) + _uleb(20) + b"\x80" * 19 + b"\x00")
    with pytest.raises(JsReError) as caught:
        summarize_wasm_bytes(bomb)
    assert caught.value.code == "invalid_params"


def test_wasm_summary_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.summary")
    assert doc, "wasm.summary is missing its docstring"
    assert "imports" in doc
    assert "exports" in doc
    assert "imported_functions" in doc
    assert "imports_truncated" in doc
    assert "pure Python" in doc
