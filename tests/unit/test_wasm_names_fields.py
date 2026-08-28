"""wasm.names decodes the WASM custom "name" section in pure Python (no wabt).

The tests hand-build modules byte for byte -- a four-byte magic, a version,
then a custom section named "name" carrying a module-name subsection (id 0)
and a function-name map (id 1) -- so nothing here depends on wat2wasm or any
other wabt tool being installed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import (
    JsReError,
    WasmClient,
    _parse_wasm_names,
)
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


def _wasm_name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _subsection(sub_id: int, content: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(content)) + content


_HEADER = b"\x00asm\x01\x00\x00\x00"


def _name_section(module: str | None, funcs: list[tuple[int, str]]) -> bytes:
    payload = _wasm_name("name")
    if module is not None:
        payload += _subsection(0, _wasm_name(module))
    if funcs:
        entries = _uleb(len(funcs))
        for index, name in funcs:
            entries += _uleb(index) + _wasm_name(name)
        payload += _subsection(1, entries)
    return _section(0, payload)


def _module(module: str | None, funcs: list[tuple[int, str]]) -> bytes:
    return _HEADER + _name_section(module, funcs)


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


def test_names_extracts_module_and_function_names_sorted(tmp_path: Path) -> None:
    """The module name and the function map come back, sorted by index."""
    blob = tmp_path / "m.wasm"
    blob.write_bytes(_module("mymod", [(5, "main"), (0, "start"), (1, "add")]))
    result = WasmClient(None).names(blob)
    assert result["present"] is True
    assert result["module_name"] == "mymod"
    assert result["items"] == [
        {"index": 0, "name": "start"},
        {"index": 1, "name": "add"},
        {"index": 5, "name": "main"},
    ]
    assert result["count"] == 3
    assert result["items_total"] == 3
    assert result["items_truncated"] is False
    assert result["truncated"] is False


def test_names_needs_no_wabt(tmp_path: Path) -> None:
    """names() reads bytes directly, so it works with wabt explicitly absent."""
    client = WasmClient(None)
    # Force both wabt tools off regardless of what is on this machine's PATH;
    # names() must not consult them.
    client._wasm2wat = None
    client._objdump = None
    blob = tmp_path / "m.wasm"
    blob.write_bytes(_module(None, [(0, "f")]))
    result = client.names(blob)
    assert result["present"] is True
    assert result["module_name"] == ""
    assert result["items"] == [{"index": 0, "name": "f"}]


def test_names_absent_section_reports_present_false(tmp_path: Path) -> None:
    """A module with no "name" section (the stripped case) is not an error."""
    blob = tmp_path / "m.wasm"
    # Header plus an unrelated custom section named "producers".
    other = _section(0, _wasm_name("producers") + b"\x00")
    blob.write_bytes(_HEADER + other)
    result = WasmClient(None).names(blob)
    assert result["present"] is False
    assert result["module_name"] == ""
    assert result["items"] == []
    assert result["count"] == 0
    assert result["truncated"] is False


def test_names_header_only_module_is_clean(tmp_path: Path) -> None:
    """Just the magic and version: present False, nothing decoded, no error."""
    blob = tmp_path / "m.wasm"
    blob.write_bytes(_HEADER)
    result = WasmClient(None).names(blob)
    assert result["present"] is False
    assert result["items"] == []


def test_names_rejects_non_wasm_input(tmp_path: Path) -> None:
    """A file without the \\0asm magic is invalid_params, not a bad parse."""
    blob = tmp_path / "not.wasm"
    blob.write_bytes(b"MZ\x90\x00 this is a PE, not wasm")
    with pytest.raises(JsReError) as excinfo:
        WasmClient(None).names(blob)
    assert excinfo.value.code == "invalid_params"


def test_names_truncated_section_flagged(tmp_path: Path) -> None:
    """A section whose declared size overruns the file sets truncated."""
    blob = tmp_path / "m.wasm"
    # Custom section claiming 200 bytes but only a few follow.
    truncated = bytes([0x00]) + _uleb(200) + _wasm_name("name") + b"\x01"
    blob.write_bytes(_HEADER + truncated)
    result = WasmClient(None).names(blob)
    assert result["truncated"] is True


def test_parse_caps_function_map_at_limit() -> None:
    """items_truncated and items_total report the whole map when it is capped."""
    module = _module(None, [(i, f"fn{i}") for i in range(6)])
    result = _parse_wasm_names(module, limit=2)
    assert result["count"] == 2
    assert result["items_total"] == 6
    assert result["items_truncated"] is True
    # The kept entries are the lowest indices after the sort.
    assert [item["index"] for item in result["items"]] == [0, 1]


def test_names_finds_section_after_other_custom_sections(tmp_path: Path) -> None:
    """A "name" section that follows another custom section is still decoded."""
    blob = tmp_path / "m.wasm"
    decoy = _section(0, _wasm_name("dylink") + b"\x00\x00")
    real = _name_section("late", [(2, "g")])
    blob.write_bytes(_HEADER + decoy + real)
    result = WasmClient(None).names(blob)
    assert result["present"] is True
    assert result["module_name"] == "late"
    assert result["items"] == [{"index": 2, "name": "g"}]


def test_tool_docstring_names_the_fields() -> None:
    doc = _tool_docstring("wasm.names")
    for field in ("present", "module_name", "items", "items_truncated"):
        assert field in doc
    assert "no wabt" in doc
