"""wasm.exports joins the export section to the type/import/function sections.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing) and assert the func-export signature resolution, the
imported-vs-defined origin, the internal-name join, non-func exports, the
4096-item cut, the filter, and that hostile input is refused rather than crashed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, list_wasm_exports_bytes
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


def _export(name: str, kind: int, index: int) -> bytes:
    return _name(name) + bytes([kind]) + _uleb(index)


def _export_sec(exports: list[tuple[str, int, int]]) -> bytes:
    return _section(7, _vec([_export(n, k, i) for n, k, i in exports]))


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


def _by_name(exports: list[dict], name: str) -> dict:
    return next(e for e in exports if e["name"] == name)


def test_wasm_exports_resolves_func_signatures_and_kinds() -> None:
    """A func export must resolve to its signature and origin; the memory import
    must not shift function indices, and non-func exports carry no signature.

    One imported func (type1) plus a memory import, two defined funcs (type0,
    type1), and exports covering a defined func, another defined func, a
    re-exported imported func, a memory and a global.
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
    export_sec = _export_sec(
        [
            ("run", 0, 1),  # defined func (type0)
            ("calc", 0, 2),  # defined func (type1)
            ("log2", 0, 0),  # re-export of the imported func (type1)
            ("memory", 2, 0),  # memory export
            ("g", 3, 0),  # global export
        ]
    )
    name_sec = _section(
        0, _name("name") + _function_names_sub([(1, "run_internal"), (2, "calc_internal")])
    )
    module = _module(_TYPE_SEC, import_sec, func_sec, export_sec, name_sec)

    result = list_wasm_exports_bytes(module)
    assert result["count"] == result["total"] == 5
    assert result["scan_capped"] is False
    assert "filtered" not in result

    run = _by_name(result["exports"], "run")
    assert run["kind"] == "func"
    assert run["index"] == 1
    assert run["origin"] == "defined"
    assert run["type_index"] == 0
    assert run["params"] == []
    assert run["results"] == []
    assert run["internal_name"] == "run_internal"

    calc = _by_name(result["exports"], "calc")
    assert calc["origin"] == "defined"
    assert calc["params"] == ["i32"]
    assert calc["results"] == ["i32"]
    assert calc["internal_name"] == "calc_internal"

    log2 = _by_name(result["exports"], "log2")
    assert log2["kind"] == "func"
    assert log2["index"] == 0
    assert log2["origin"] == "imported"
    assert log2["params"] == ["i32"]
    assert log2["results"] == ["i32"]
    # The name section named only the defined funcs, so the re-exported import
    # carries no internal_name -- a bonus, not a requirement.
    assert "internal_name" not in log2

    mem = _by_name(result["exports"], "memory")
    assert mem["kind"] == "memory"
    assert mem["index"] == 0
    assert "origin" not in mem
    assert "params" not in mem

    glob = _by_name(result["exports"], "g")
    assert glob["kind"] == "global"
    assert "params" not in glob


def test_wasm_exports_filters_by_name() -> None:
    func_sec = _section(3, _vec([_uleb(0), _uleb(1)]))
    export_sec = _export_sec([("run", 0, 0), ("decrypt", 0, 1)])
    module = _module(_TYPE_SEC, func_sec, export_sec)

    result = list_wasm_exports_bytes(module, contains="decrypt")
    assert result["filtered"] is True
    assert result["query"] == "decrypt"
    assert [e["name"] for e in result["exports"]] == ["decrypt"]
    assert result["count"] == result["total"] == 1


def test_wasm_exports_flags_an_unresolvable_signature() -> None:
    one_type = _section(1, _vec([b"\x60\x00\x00"]))
    func_sec = _section(3, _vec([_uleb(5)]))  # defined func points at a missing type
    export_sec = _export_sec([("x", 0, 0)])
    module = _module(one_type, func_sec, export_sec)

    result = list_wasm_exports_bytes(module)
    entry = result["exports"][0]
    assert entry["signature_unknown"] is True
    assert entry["params"] == []
    assert entry["results"] == []
    assert entry["origin"] == "defined"


def test_wasm_exports_reports_a_module_with_no_exports() -> None:
    module = _module(_TYPE_SEC, _section(3, _vec([_uleb(0)])))
    result = list_wasm_exports_bytes(module)
    assert result["exports"] == []
    assert result["count"] == result["total"] == 0
    assert result["scan_capped"] is False


def test_wasm_exports_caps_a_huge_export_section() -> None:
    export_sec = _export_sec([("e", 3, 0)] * (_MAX_ITEMS + 5))
    module = _module(export_sec)
    result = list_wasm_exports_bytes(module)
    assert result["count"] == _MAX_ITEMS
    assert result["total"] == _MAX_ITEMS + 5
    assert result["scan_capped"] is True


def test_wasm_exports_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as caught:
        list_wasm_exports_bytes(b"MZ\x90\x00this is a PE, not wasm")
    assert caught.value.code == "invalid_params"


def test_wasm_exports_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.exports")
    assert doc, "wasm.exports is missing its docstring"
    assert "origin" in doc
    assert "params" in doc
    assert "internal_name" in doc
    assert "signature_unknown" in doc
    assert "pure Python" in doc
