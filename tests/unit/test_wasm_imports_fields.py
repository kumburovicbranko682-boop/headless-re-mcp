"""wasm.imports decodes every import kind's descriptor, not just the functions.

The parser takes no external tool, so these build WebAssembly modules by hand
(LEB128 + section framing) and assert the func-import signature join, the
memory/table limits (including the threads shared flag), global mutability, the
per-kind index spaces, the module roll-up, the 4096-item cut, the filter, and
that hostile input is refused rather than crashed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, list_wasm_imports_bytes
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


def _func_import(module: str, field: str, type_index: int) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(type_index)


def _table_import(module: str, field: str, reftype: int, flags: int, *dims: int) -> bytes:
    return (
        _name(module) + _name(field) + b"\x01" + bytes([reftype, flags])
        + b"".join(_uleb(d) for d in dims)
    )


def _memory_import(module: str, field: str, flags: int, *dims: int) -> bytes:
    return _name(module) + _name(field) + b"\x02" + bytes([flags]) + b"".join(
        _uleb(d) for d in dims
    )


def _global_import(module: str, field: str, valtype: int, mutable: int) -> bytes:
    return _name(module) + _name(field) + b"\x03" + bytes([valtype, mutable])


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


def _by_name(imports: list[dict], name: str) -> dict:
    return next(e for e in imports if e["name"] == name)


def test_wasm_imports_decodes_every_kind() -> None:
    """One import of each kind: the func joins its signature, the memory keeps
    its page limits and shared flag, the table its reftype, the global its
    mutability -- and each kind numbers its own index space from zero.
    """
    import_sec = _section(
        2,
        _vec(
            [
                _func_import("env", "log", 1),
                _func_import("wasi_snapshot_preview1", "fd_write", 0),
                # shared memory: flags 0x03 = has-maximum | shared
                _memory_import("env", "memory", 0x03, 17, 256),
                _table_import("env", "table", 0x70, 0x00, 4),  # funcref, no max
                _global_import("env", "stack_ptr", 0x7F, 0x01),  # mutable i32
            ]
        ),
    )
    module = _module(_TYPE_SEC, import_sec)

    result = list_wasm_imports_bytes(module)
    assert result["count"] == result["total"] == 5
    assert result["scan_capped"] is False
    assert "filtered" not in result
    assert result["func_count"] == 2
    assert result["memory_count"] == 1
    assert result["table_count"] == 1
    assert result["global_count"] == 1
    assert result["modules"] == ["env", "wasi_snapshot_preview1"]
    assert result["module_count"] == 2

    log = _by_name(result["imports"], "log")
    assert log["module"] == "env"
    assert log["kind"] == "func"
    assert log["index"] == 0
    assert log["type_index"] == 1
    assert log["params"] == ["i32"]
    assert log["results"] == ["i32"]
    assert "signature_unknown" not in log

    fd_write = _by_name(result["imports"], "fd_write")
    assert fd_write["module"] == "wasi_snapshot_preview1"
    assert fd_write["index"] == 1  # second func import, same func index space
    assert fd_write["params"] == []
    assert fd_write["results"] == []

    mem = _by_name(result["imports"], "memory")
    assert mem["kind"] == "memory"
    assert mem["index"] == 0  # memory space starts over at zero
    assert mem["initial"] == 17
    assert mem["maximum"] == 256
    assert mem["shared"] is True
    assert "params" not in mem

    table = _by_name(result["imports"], "table")
    assert table["kind"] == "table"
    assert table["reftype"] == "funcref"
    assert table["initial"] == 4
    assert "maximum" not in table
    assert "shared" not in table

    glob = _by_name(result["imports"], "stack_ptr")
    assert glob["kind"] == "global"
    assert glob["valtype"] == "i32"
    assert glob["mutable"] is True


def test_wasm_imports_immutable_global_and_unshared_memory() -> None:
    import_sec = _section(
        2,
        _vec(
            [
                _memory_import("env", "mem", 0x00, 1),  # no maximum, not shared
                _global_import("env", "base", 0x7C, 0x00),  # immutable f64
            ]
        ),
    )
    result = list_wasm_imports_bytes(_module(import_sec))
    mem = _by_name(result["imports"], "mem")
    assert mem["initial"] == 1
    assert "maximum" not in mem
    assert "shared" not in mem
    glob = _by_name(result["imports"], "base")
    assert glob["valtype"] == "f64"
    assert glob["mutable"] is False


def test_wasm_imports_flags_an_unresolvable_signature() -> None:
    # The func import points past the type section: unknown, not mis-decoded.
    import_sec = _section(2, _vec([_func_import("env", "mystery", 9)]))
    result = list_wasm_imports_bytes(_module(_TYPE_SEC, import_sec))
    entry = result["imports"][0]
    assert entry["signature_unknown"] is True
    assert entry["params"] == []
    assert entry["results"] == []
    assert entry["type_index"] == 9


def test_wasm_imports_filters_by_module_name_and_kind() -> None:
    import_sec = _section(
        2,
        _vec(
            [
                _func_import("env", "log", 0),
                _func_import("wasi_snapshot_preview1", "fd_write", 0),
                _memory_import("env", "memory", 0x00, 1),
            ]
        ),
    )
    module = _module(_TYPE_SEC, import_sec)

    by_module = list_wasm_imports_bytes(module, contains="wasi")
    assert by_module["filtered"] is True
    assert by_module["query"] == "wasi"
    assert [e["name"] for e in by_module["imports"]] == ["fd_write"]
    assert by_module["count"] == by_module["total"] == 1
    # The per-kind totals stay structural: the filter narrows the listing only.
    assert by_module["func_count"] == 2

    by_kind = list_wasm_imports_bytes(module, contains="memory")
    assert {e["name"] for e in by_kind["imports"]} == {"memory"}


def test_wasm_imports_reports_a_module_with_no_imports() -> None:
    module = _module(_TYPE_SEC, _section(3, _vec([_uleb(0)])))
    result = list_wasm_imports_bytes(module)
    assert result["imports"] == []
    assert result["count"] == result["total"] == 0
    assert result["scan_capped"] is False
    assert result["modules"] == []
    assert result["module_count"] == 0


def test_wasm_imports_caps_a_huge_import_section() -> None:
    entries = [_global_import("env", "g", 0x7F, 0x00)] * (_MAX_ITEMS + 5)
    module = _module(_section(2, _vec(entries)))
    result = list_wasm_imports_bytes(module)
    assert result["count"] == _MAX_ITEMS
    assert result["total"] == _MAX_ITEMS + 5
    assert result["scan_capped"] is True
    # The whole section is still walked, so the structural totals stay exact.
    assert result["global_count"] == _MAX_ITEMS + 5


def test_wasm_imports_rejects_a_non_module() -> None:
    with pytest.raises(JsReError) as caught:
        list_wasm_imports_bytes(b"MZ\x90\x00this is a PE, not wasm")
    assert caught.value.code == "invalid_params"


def test_wasm_imports_rejects_an_unknown_external_kind() -> None:
    bad = _name("env") + _name("x") + b"\x09"
    module = _module(_section(2, _vec([bad])))
    with pytest.raises(JsReError) as caught:
        list_wasm_imports_bytes(module)
    assert caught.value.code == "invalid_params"


def test_wasm_imports_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.imports")
    assert doc, "wasm.imports is missing its docstring"
    assert "module" in doc
    assert "shared" in doc
    assert "mutable" in doc
    assert "signature_unknown" in doc
    assert "pure Python" in doc
