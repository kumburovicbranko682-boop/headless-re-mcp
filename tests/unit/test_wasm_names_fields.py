"""wasm.names resolves function indices to names from the module's name section.

wasm.summary reports bare indices; the ``name`` custom section (kept by
emscripten -g and debug builds) maps those indices to symbols. wasm.names
decodes it in-process, no wabt. These build a real name section (module-name
subsection, function-name namemap, and an extra subsection that must be skipped)
and cover the decode, the filter/paging, the stripped-module case, the malformed
subsection, and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import WasmParseError, parse_function_names
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


def _subsection(sub_id: int, body: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(body)) + body


def _namemap(funcs: list[tuple[int, str]]) -> bytes:
    body = _uleb(len(funcs))
    for index, name in funcs:
        body += _uleb(index) + _name(name)
    return body


def _name_section(
    module_name: str | None,
    funcs: list[tuple[int, str]],
    *,
    extra: tuple[int, bytes] | None = None,
) -> bytes:
    body = _name("name")
    if module_name is not None:
        body += _subsection(0, _name(module_name))
    body += _subsection(1, _namemap(funcs))
    if extra is not None:
        body += _subsection(extra[0], extra[1])
    return _section(0, body)


def _module(name_section: bytes) -> bytes:
    # A dummy type section in front proves the name section is found by walking.
    return _HEADER + _section(1, _uleb(0)) + name_section


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


def test_parse_function_names_decodes_module_and_functions() -> None:
    module = _module(
        _name_section(
            "my_module",
            [(0, "foo"), (1, "bar"), (2, "malloc")],
            extra=(2, b"\x00"),  # a local-names subsection, must be skipped
        )
    )
    module_name, entries, has_section, capped = parse_function_names(module)
    assert has_section is True
    assert module_name == "my_module"
    assert capped is False
    assert {(e["index"], e["name"]) for e in entries} == {
        (0, "foo"),
        (1, "bar"),
        (2, "malloc"),
    }


def test_parse_function_names_filter_is_case_sensitive_substring() -> None:
    module = _module(_name_section(None, [(0, "foo"), (1, "malloc"), (2, "free")]))
    _mn, entries, _has, _capped = parse_function_names(module, name_filter="ma")
    assert [e["name"] for e in entries] == ["malloc"]
    # Case-sensitive: an upper-case needle does not match a lower-case symbol.
    _mn2, entries2, _h2, _c2 = parse_function_names(module, name_filter="MALLOC")
    assert entries2 == []


def test_parse_function_names_absent_section_is_the_answer() -> None:
    # A module with only a (non-name) custom section and no name section.
    other = _section(0, _name("producers") + b"\x00\x01")
    module = _HEADER + _section(1, _uleb(0)) + other
    module_name, entries, has_section, capped = parse_function_names(module)
    assert has_section is False
    assert module_name == ""
    assert entries == []
    assert capped is False


def test_parse_function_names_rejects_overrunning_subsection() -> None:
    # A function-names subsection that claims more bytes than the section holds.
    body = _name("name") + bytes([1]) + _uleb(100)
    module = _HEADER + _section(0, body)
    with pytest.raises(WasmParseError):
        parse_function_names(module)


def test_client_names_pages_and_reports_totals(tmp_path: Path) -> None:
    module = _module(
        _name_section("m", [(index, f"fn_{index}") for index in range(25)])
    )
    path = tmp_path / "mod.wasm"
    path.write_bytes(module)
    page = WasmClient(None).names(path, offset=0, limit=10)
    assert page["has_name_section"] is True
    assert page["module_name"] == "m"
    assert page["count"] == 10
    assert page["total"] == 25
    assert page["has_more"] is True
    assert page["offset"] == 0
    # Sorted by index, so the first page starts at fn_0.
    assert page["names"][0] == {"index": 0, "name": "fn_0"}


def test_client_names_stripped_module_reports_empty(tmp_path: Path) -> None:
    module = _HEADER + _section(1, _uleb(0))  # no name section at all
    path = tmp_path / "stripped.wasm"
    path.write_bytes(module)
    result = WasmClient(None).names(path)
    assert result["has_name_section"] is False
    assert result["names"] == []
    assert result["total"] == 0


def test_client_names_non_wasm_is_invalid_params(tmp_path: Path) -> None:
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b"not a wasm module")
    with pytest.raises(jsre_client.JsReError) as info:
        WasmClient(None).names(bad)
    assert info.value.code == "invalid_params"


def test_wasm_names_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("wasm.names").split())
    assert "without wabt" in doc
    assert "has_name_section" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "wasm.names" in _READ_ONLY_NAMES
