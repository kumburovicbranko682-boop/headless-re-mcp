"""wasm.names decodes the module/function names from the name custom section.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing + a "name" custom section with module-name and
function-name subsections) and assert the has_name_section signal, the
index/name shape, the contains filter, the 4096 cap, and that hostile input is
refused rather than crashed on.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, extract_wasm_names_bytes
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


def _section(section_id: int, content: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(content)) + content


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _subsection(sub_id: int, content: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(content)) + content


def _module_name_sub(text: str) -> bytes:
    return _subsection(0, _name(text))


def _function_names_sub(entries: list[tuple[int, str]]) -> bytes:
    body = _uleb(len(entries)) + b"".join(_uleb(idx) + _name(nm) for idx, nm in entries)
    return _subsection(1, body)


def _name_section(*subsections: bytes) -> bytes:
    """A custom section (id 0) literally named "name" holding the subsections."""
    return _section(0, _name("name") + b"".join(subsections))


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


def test_wasm_names_decodes_module_and_function_names() -> None:
    """The module name and each (index, name) pair must come back in order.

    A dev build maps function indices to readable names; assert the module name
    is surfaced and every function-name entry keeps its index, so an internal
    function is identifiable by name and not just by index.
    """
    module = _module(
        _name_section(
            _module_name_sub("app.wasm"),
            _function_names_sub([(0, "_start"), (3, "decryptPayload"), (7, "sendBeacon")]),
        )
    )
    result = extract_wasm_names_bytes(module)
    assert result["has_name_section"] is True
    assert result["module_name"] == "app.wasm"
    assert result["count"] == 3
    assert result["total"] == 3
    assert result["scan_capped"] is False
    assert result["functions"] == [
        {"index": 0, "name": "_start"},
        {"index": 3, "name": "decryptPayload"},
        {"index": 7, "name": "sendBeacon"},
    ]
    assert "filtered" not in result


def test_wasm_names_reports_a_stripped_module() -> None:
    """A module with no name section must say so, not pretend it is empty.

    has_name_section false is a different answer from "a name section with no
    function names": one means stripped, the other means present-but-empty.
    """
    # A lone type section, no custom "name" section.
    module = _module(_section(1, _uleb(0)))
    result = extract_wasm_names_bytes(module)
    assert result["has_name_section"] is False
    assert result["module_name"] is None
    assert result["functions"] == []
    assert result["count"] == 0
    assert result["total"] == 0


def test_wasm_names_ignores_a_non_name_custom_section() -> None:
    """A custom section that is not literally "name" must not be decoded."""
    other = _section(0, _name("producers") + b"\x01\x02\x03")
    module = _module(other)
    result = extract_wasm_names_bytes(module)
    assert result["has_name_section"] is False
    assert result["functions"] == []


def test_wasm_names_skips_unrelated_subsections() -> None:
    """Local/label/type name subsections are skipped by size, functions kept.

    Wedge an unknown subsection (id 2, local names) between the module-name and
    function-names subsections; the parser must step over it by its declared
    length and still recover the function names that follow.
    """
    local_names = _subsection(2, b"\x00")  # empty indirectnamemap-ish blob
    module = _module(
        _name_section(
            _module_name_sub("m"),
            local_names,
            _function_names_sub([(1, "keep_me")]),
        )
    )
    result = extract_wasm_names_bytes(module)
    assert result["module_name"] == "m"
    assert result["functions"] == [{"index": 1, "name": "keep_me"}]


def test_wasm_names_contains_filters_to_matches() -> None:
    """A substring filter must narrow the function names, case-insensitively."""
    module = _module(
        _name_section(
            _function_names_sub(
                [(0, "main"), (1, "aesEncrypt"), (2, "aesDecrypt"), (3, "render")]
            ),
        )
    )
    hits = extract_wasm_names_bytes(module, contains="AES")
    assert [item["name"] for item in hits["functions"]] == ["aesEncrypt", "aesDecrypt"]
    assert hits["filtered"] is True
    assert hits["query"] == "AES"
    assert hits["total"] == 2

    plain = extract_wasm_names_bytes(module)
    assert "filtered" not in plain
    assert plain["total"] == 4


def test_wasm_names_caps_a_flood_of_names() -> None:
    """More than the cap of names must clip the list and flag scan_capped."""
    entries = [(index, f"fn{index}") for index in range(_MAX_ITEMS + 5)]
    module = _module(_name_section(_function_names_sub(entries)))
    result = extract_wasm_names_bytes(module)
    assert result["count"] == _MAX_ITEMS
    assert result["total"] == _MAX_ITEMS + 5
    assert result["scan_capped"] is True


def test_wasm_names_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as excinfo:
        extract_wasm_names_bytes(b"not a wasm module at all")
    assert excinfo.value.code == "invalid_params"


def test_wasm_names_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.names")
    assert doc, "wasm.names is missing its docstring"
    assert "has_name_section" in doc
    assert "module_name" in doc
    assert "functions" in doc
    assert "contains" in doc
    assert "scan_capped" in doc
