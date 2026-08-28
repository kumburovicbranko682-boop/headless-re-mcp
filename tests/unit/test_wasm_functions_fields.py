"""wasm.functions lists the function index space with resolved signatures."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_functions
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


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*, bad_types: bool = False, with_names: bool = True) -> bytes:
    if bad_types:
        # A type section whose single entry is an array type (0x5e), which the
        # parser does not model -> types unresolved.
        type_sec = _section(1, _uleb(1) + b"\x5e")
    else:
        type0 = b"\x60" + _vec([b"\x7f", b"\x7f"]) + _vec([b"\x7f"])  # (i32,i32)->i32
        type1 = b"\x60" + _vec([]) + _vec([])  # ()->()
        type_sec = _section(1, _vec([type0, type1]))

    func_import = _name("env") + _name("log") + b"\x00" + _uleb(1)  # func, type 1
    mem_import = _name("env") + _name("memory") + b"\x02" + b"\x00" + _uleb(1)  # memory
    import_sec = _section(2, _vec([func_import, mem_import]))

    func_sec = _section(3, _vec([_uleb(0), _uleb(1)]))  # defined: type 0, type 1

    module = b"\x00asm\x01\x00\x00\x00" + type_sec + import_sec + func_sec
    if with_names:
        namemap = _uleb(3) + (
            _uleb(0) + _name("imported_log")
            + _uleb(1) + _name("add")
            + _uleb(2) + _name("noop")
        )
        name_sub = b"\x01" + _uleb(len(namemap)) + namemap
        module += _section(0, _name("name") + name_sub)
    return module


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


def test_functions_walk_the_index_space_imports_first() -> None:
    result = list_wasm_functions(_module())

    assert result["total"] == 3
    assert result["imported_count"] == 1
    assert result["defined_count"] == 2
    assert result["types_resolved"] is True

    rows = {row["index"]: row for row in result["functions"]}
    # index 0: the function import (the memory import does not take an index).
    assert rows[0]["kind"] == "imported"
    assert rows[0]["module"] == "env"
    assert rows[0]["name"] == "log"
    assert rows[0]["type_index"] == 1
    assert rows[0]["params"] == []
    assert rows[0]["results"] == []
    assert rows[0]["debug_name"] == "imported_log"

    # index 1: first defined function, (i32,i32)->i32, named in the name section.
    assert rows[1]["kind"] == "defined"
    assert rows[1]["type_index"] == 0
    assert rows[1]["params"] == ["i32", "i32"]
    assert rows[1]["results"] == ["i32"]
    assert rows[1]["name"] == "add"

    assert rows[2]["kind"] == "defined"
    assert rows[2]["params"] == []
    assert rows[2]["name"] == "noop"


def test_functions_degrade_when_types_do_not_resolve() -> None:
    result = list_wasm_functions(_module(bad_types=True))
    assert result["types_resolved"] is False
    # Functions are still listed with their type index, just no signature.
    row = result["functions"][0]
    assert row["type_index"] is not None
    assert "params" not in row


def test_functions_survive_a_module_with_no_names() -> None:
    result = list_wasm_functions(_module(with_names=False))
    assert result["total"] == 3
    assert "name" not in result["functions"][2]  # defined func, no name section
    assert "debug_name" not in result["functions"][0]


def test_functions_page_the_listing() -> None:
    result = list_wasm_functions(_module(), offset=1, limit=1)
    assert result["count"] == 1
    assert result["total"] == 3
    assert result["offset"] == 1
    assert result["has_more"] is True
    assert result["functions"][0]["index"] == 1


def test_functions_on_a_module_with_no_function_section() -> None:
    # magic + version + a lone func import, no function section.
    func_import = _name("env") + _name("log") + b"\x00" + _uleb(0)
    type_sec = _section(1, _vec([b"\x60" + _vec([]) + _vec([])]))
    import_sec = _section(2, _vec([func_import]))
    module = b"\x00asm\x01\x00\x00\x00" + type_sec + import_sec
    result = list_wasm_functions(module)
    assert result["total"] == 1
    assert result["imported_count"] == 1
    assert result["defined_count"] == 0


def test_wasm_client_functions_needs_no_wabt(tmp_path: Path) -> None:
    module = tmp_path / "m.wasm"
    module.write_bytes(_module())
    result = WasmClient(None).functions(module)
    assert result["total"] == 3
    assert result["imported_count"] == 1


def test_wasm_client_functions_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"MZ not a module")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).functions(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_functions_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.functions")
    assert "imported_count" in doc
    assert "defined_count" in doc
    assert "params" in doc
    assert "types_resolved" in doc
    assert "has_more" in doc
