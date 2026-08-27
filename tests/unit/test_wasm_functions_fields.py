"""wasm.functions joins the type/import/function/name sections into a signature table.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing) and assert the imported-vs-defined split, the resolved
param/result signatures, the name-section join, the 4096-item cut, and that
hostile input is refused rather than crashed on.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, list_wasm_functions_bytes
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


def _subsection(sub_id: int, content: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(content)) + content


def _function_names_sub(entries: list[tuple[int, str]]) -> bytes:
    body = _uleb(len(entries)) + b"".join(_uleb(idx) + _name(nm) for idx, nm in entries)
    return _subsection(1, body)


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


# type0 = () -> (); type1 = (i32) -> (i32)
_TYPE_SEC = _section(1, _vec([b"\x60\x00\x00", b"\x60\x01\x7f\x01\x7f"]))


def _by_index(functions: list[dict], index: int) -> dict:
    return next(fn for fn in functions if fn["index"] == index)


def test_wasm_functions_joins_imports_defs_and_names() -> None:
    """The table must split imported from defined, resolve each signature, and
    attach names by the global function index (imports first).

    An imported func of type1 and an imported memory (which takes no function
    index), then two defined funcs of type0/type1, with a name section naming
    all three functions. The memory import must not shift the function indices,
    the (i32)->(i32) signature must resolve, and each name must land on the
    right index.
    """
    import_sec = _section(
        2,
        _vec(
            [
                _name("env") + _name("log") + b"\x00" + _uleb(1),  # func, type1
                _name("env") + _name("mem") + b"\x02" + b"\x00" + _uleb(1),  # memory
            ]
        ),
    )
    func_sec = _section(3, _vec([_uleb(0), _uleb(1)]))  # defined funcs: type0, type1
    name_sec = _section(
        0,
        _name("name")
        + _function_names_sub([(0, "log_import"), (1, "run"), (2, "helper")]),
    )
    module = _module(_TYPE_SEC, import_sec, func_sec, name_sec)

    result = list_wasm_functions_bytes(module)
    assert result["imported_count"] == 1
    assert result["defined_count"] == 2
    assert result["total"] == result["count"] == 3
    assert result["scan_capped"] is False
    assert "filtered" not in result

    imported = _by_index(result["functions"], 0)
    assert imported["kind"] == "imported"
    assert imported["type_index"] == 1
    assert imported["params"] == ["i32"]
    assert imported["results"] == ["i32"]
    assert imported["module"] == "env"
    assert imported["import_name"] == "log"
    assert imported["name"] == "log_import"

    first_def = _by_index(result["functions"], 1)
    assert first_def["kind"] == "defined"
    assert first_def["type_index"] == 0
    assert first_def["params"] == []
    assert first_def["results"] == []
    assert first_def["name"] == "run"
    assert "module" not in first_def  # defined funcs carry no import fields

    second_def = _by_index(result["functions"], 2)
    assert second_def["type_index"] == 1
    assert second_def["params"] == ["i32"]
    assert second_def["results"] == ["i32"]
    assert second_def["name"] == "helper"


def test_wasm_functions_filters_by_name() -> None:
    """contains must narrow to matching functions, during assembly."""
    func_sec = _section(3, _vec([_uleb(0), _uleb(1)]))
    name_sec = _section(
        0, _name("name") + _function_names_sub([(0, "run"), (1, "decryptPayload")])
    )
    module = _module(_TYPE_SEC, func_sec, name_sec)

    result = list_wasm_functions_bytes(module, contains="decrypt")
    assert result["filtered"] is True
    assert result["query"] == "decrypt"
    assert [fn["name"] for fn in result["functions"]] == ["decryptPayload"]
    assert result["total"] == result["count"] == 1
    # The structural totals still describe the whole module, not the match set.
    assert result["defined_count"] == 2


def test_wasm_functions_flags_an_unresolvable_signature() -> None:
    """A function whose type index is out of range must be marked, not guessed.

    One type is defined but the function section points at type 5; the entry
    must carry signature_unknown with empty params/results rather than crash.
    """
    one_type = _section(1, _vec([b"\x60\x00\x00"]))
    func_sec = _section(3, _vec([_uleb(5)]))
    module = _module(one_type, func_sec)

    result = list_wasm_functions_bytes(module)
    entry = result["functions"][0]
    assert entry["signature_unknown"] is True
    assert entry["params"] == []
    assert entry["results"] == []


def test_wasm_functions_caps_a_huge_function_section() -> None:
    """A module with more than 4096 defined functions must cap the emitted list
    while still reporting the true structural total."""
    func_sec = _section(3, _vec([_uleb(0)] * (_MAX_ITEMS + 5)))
    module = _module(_TYPE_SEC, func_sec)

    result = list_wasm_functions_bytes(module)
    assert result["count"] == _MAX_ITEMS
    assert result["scan_capped"] is True
    assert result["defined_count"] == _MAX_ITEMS + 5
    assert result["total"] == _MAX_ITEMS + 5


def test_wasm_functions_reports_a_module_with_no_functions() -> None:
    module = _module(_TYPE_SEC)
    result = list_wasm_functions_bytes(module)
    assert result["functions"] == []
    assert result["count"] == 0
    assert result["imported_count"] == 0
    assert result["defined_count"] == 0


def test_wasm_functions_survives_a_corrupt_name_section() -> None:
    """A bad name section must not sink the listing -- names are a bonus join.

    The function still lists with its resolved signature; it simply carries no
    name.
    """
    func_sec = _section(3, _vec([_uleb(1)]))
    # A name section whose function-names subsection claims entries but ends.
    bad_name = _section(0, _name("name") + _subsection(1, _uleb(3)))
    module = _module(_TYPE_SEC, func_sec, bad_name)

    result = list_wasm_functions_bytes(module)
    assert result["count"] == 1
    entry = result["functions"][0]
    assert entry["params"] == ["i32"]
    assert "name" not in entry


def test_wasm_functions_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as caught:
        list_wasm_functions_bytes(b"MZ\x90\x00this is a PE, not wasm")
    assert caught.value.code == "invalid_params"


def test_wasm_functions_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.functions")
    assert doc, "wasm.functions is missing its docstring"
    assert "params" in doc
    assert "results" in doc
    assert "imported" in doc
    assert "type_index" in doc
    assert "signature_unknown" in doc
    assert "pure Python" in doc
