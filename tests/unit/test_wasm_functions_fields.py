"""wasm.functions builds the module's function table without wabt.

This is the inventory companion to wasm.summary / wasm.names: it joins the type,
import, function and code sections into one function-index-ordered table and
layers export names and the name section over it. The tests drive a hand-encoded
module through the parser, the client and the service, checking index-space math
(imports first, then locals), signature rendering, code sizes, export/name
resolution and its fallbacks, include_imports, name_filter over names and
module.field, paging, the pre-filter summary, best-effort degradation on a
truncated section, non-wasm rejection, and the tool docstring / read-only bit.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import parse_functions
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _nm(text: str) -> bytes:
    raw = text.encode()
    return _uleb(len(raw)) + raw


def _section(sec_id: int, body: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(body)) + body


def _build_module(*, with_names: bool = True) -> bytes:
    # type 0: (i32, i32) -> (i32); type 1: () -> ()
    types = _uleb(2)
    types += b"\x60" + _uleb(2) + b"\x7f\x7f" + _uleb(1) + b"\x7f"
    types += b"\x60" + _uleb(0) + _uleb(0)
    # one function import: env.log, type 1 -> function index 0
    imports = _uleb(1) + _nm("env") + _nm("log") + b"\x00" + _uleb(1)
    # two local functions: type 0 (index 1), type 1 (index 2)
    funcs = _uleb(2) + _uleb(0) + _uleb(1)
    # export "add" -> function index 1 (the first local)
    exports = _uleb(1) + _nm("add") + b"\x00" + _uleb(1)
    # code: each body is (locals count 0)(end); size prefixed
    body = _uleb(0) + b"\x0b"
    code = _uleb(2) + _uleb(len(body)) + body + _uleb(len(body)) + body

    module = b"\x00asm" + b"\x01\x00\x00\x00"
    module += _section(1, types)
    module += _section(2, imports)
    module += _section(3, funcs)
    module += _section(7, exports)
    module += _section(10, code)
    if with_names:
        # name index 1 -> "add_impl", index 2 -> "helper" (import index 0 unnamed)
        namemap = _uleb(2) + _uleb(1) + _nm("add_impl") + _uleb(2) + _nm("helper")
        sub = bytes([1]) + _uleb(len(namemap)) + namemap
        module += _section(0, _nm("name") + sub)
    return module


def test_parse_functions_index_space_and_signatures() -> None:
    rows, summary, scan_capped = parse_functions(_build_module())
    assert scan_capped is False
    by_index = {r["index"]: r for r in rows}

    imp = by_index[0]
    assert imp["origin"] == "import"
    assert imp["module"] == "env" and imp["field"] == "log"
    assert imp["signature"] == "() -> ()"
    assert imp["name"] == ""  # unnamed import, not exported
    assert imp["exported"] is False
    assert "code_size" not in imp

    add = by_index[1]
    assert add["origin"] == "local"
    assert add["signature"] == "(i32, i32) -> (i32)"
    assert add["params"] == ["i32", "i32"] and add["results"] == ["i32"]
    assert add["name"] == "add_impl"  # name section wins over export name
    assert add["exported"] is True and add["export_name"] == "add"
    assert add["code_size"] == 2

    helper = by_index[2]
    assert helper["origin"] == "local"
    assert helper["name"] == "helper"
    assert helper["exported"] is False
    assert helper["code_size"] == 2

    assert summary == {
        "imported_total": 1,
        "local_total": 2,
        "type_count": 2,
        "has_type_section": True,
        "has_function_section": True,
        "has_code_section": True,
    }


def test_parse_functions_name_falls_back_to_export_when_unnamed() -> None:
    rows, _summary, _capped = parse_functions(_build_module(with_names=False))
    add = next(r for r in rows if r["index"] == 1)
    # No name section, but it is exported: name falls back to the export name.
    assert add["name"] == "add"
    assert add["export_name"] == "add"
    helper = next(r for r in rows if r["index"] == 2)
    assert helper["name"] == ""  # neither named nor exported


def test_parse_functions_include_imports_false_and_name_filter() -> None:
    module = _build_module()
    locals_only, _s, _c = parse_functions(module, include_imports=False)
    assert {r["origin"] for r in locals_only} == {"local"}
    assert [r["index"] for r in locals_only] == [1, 2]

    just_helper, _s2, _c2 = parse_functions(module, name_filter="helper")
    assert [r["index"] for r in just_helper] == [2]

    # module.field is searchable, so an import is found by its host interface.
    by_import, _s3, _c3 = parse_functions(module, name_filter="env.log")
    assert [r["index"] for r in by_import] == [0]


def test_parse_functions_malformed_code_section_degrades() -> None:
    # Honest section framing, but the second code entry declares a body far larger
    # than the section holds. _iter_sections is happy (the section's own size is
    # correct); the inner walk catches the overrun and keeps what it read rather
    # than raising, so the table still lists both local functions.
    types = (
        _uleb(2)
        + b"\x60" + _uleb(2) + b"\x7f\x7f" + _uleb(1) + b"\x7f"
        + b"\x60" + _uleb(0) + _uleb(0)
    )
    imports = _uleb(1) + _nm("env") + _nm("log") + b"\x00" + _uleb(1)
    funcs = _uleb(2) + _uleb(0) + _uleb(1)
    body = _uleb(0) + b"\x0b"
    code = _uleb(2) + _uleb(len(body)) + body + _uleb(200)  # 2nd entry overruns
    module = b"\x00asm" + b"\x01\x00\x00\x00"
    module += _section(1, types) + _section(2, imports) + _section(3, funcs) + _section(10, code)

    rows, summary, _capped = parse_functions(module)
    assert summary["has_code_section"] is True
    locals_ = [r for r in rows if r["origin"] == "local"]
    assert [r["index"] for r in locals_] == [1, 2]
    # Only the first local's body size was read before the malformed entry.
    assert locals_[0]["code_size"] == 2
    assert "code_size" not in locals_[1]


def test_client_functions_pages_and_reports_total(tmp_path: Path) -> None:
    path = tmp_path / "m.wasm"
    path.write_bytes(_build_module())
    client = WasmClient(None)
    page = client.functions(path, offset=0, limit=2)
    assert page["total"] == 3
    assert page["count"] == 2
    assert page["has_more"] is True
    assert page["offset"] == 0
    assert page["summary"]["imported_total"] == 1
    rest = client.functions(path, offset=2, limit=2)
    assert rest["count"] == 1
    assert rest["has_more"] is False
    assert rest["functions"][0]["index"] == 2


def test_service_wasm_functions_ok_and_rejects_non_wasm(tmp_path: Path) -> None:
    good = tmp_path / "m.wasm"
    good.write_bytes(_build_module())
    service = AnalysisService()
    try:
        ok = service.wasm_functions(str(good), include_imports=False)
        assert ok.ok and ok.data is not None
        assert [r["index"] for r in ok.data["functions"]] == [1, 2]

        bad = tmp_path / "not.wasm"
        bad.write_bytes(b"this is not a wasm module at all")
        rejected = service.wasm_functions(str(bad))
        assert rejected.ok is False
    finally:
        service.close_all()


def test_wasm_functions_tool_docstring_and_read_only() -> None:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    doc = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if (
                            kw.arg == "name"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value == "wasm.functions"
                        ):
                            doc = ast.get_docstring(node) or ""
    flat = " ".join(doc.split())
    assert "signature" in flat and "code_size" in flat and "include_imports" in flat
    assert "r2.functions" in flat

    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "wasm.functions" in _READ_ONLY_NAMES
