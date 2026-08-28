"""Tests for WasmClient.functions, the module's whole function table.

Like the summary/names tests these hand-build tiny modules so the parser runs on
a box with no wabt: the point of wasm.functions is that it reads the binary
directly, stitching the Type, Import, Function, Export, Code and name sections
into one per-function inventory keyed by the function index space.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

I32 = 0x7F
I64 = 0x7E
F64 = 0x7C


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


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + (1).to_bytes(4, "little") + b"".join(sections)


def _valtypes(vts: list[int]) -> bytes:
    return _uleb(len(vts)) + bytes(vts)


def _functype(params: list[int], results: list[int]) -> bytes:
    return bytes([0x60]) + _valtypes(params) + _valtypes(results)


def _type_section(*functypes: bytes) -> bytes:
    return _section(1, _uleb(len(functypes)) + b"".join(functypes))


def _import_func(module: str, field: str, type_index: int) -> bytes:
    return _name(module) + _name(field) + bytes([0x00]) + _uleb(type_index)


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _function_section(*type_indices: int) -> bytes:
    return _section(3, _uleb(len(type_indices)) + b"".join(_uleb(t) for t in type_indices))


def _export_func(name: str, index: int) -> bytes:
    return _name(name) + bytes([0x00]) + _uleb(index)


def _export_section(*exports: bytes) -> bytes:
    return _section(7, _uleb(len(exports)) + b"".join(exports))


def _code_body(local_groups: list[tuple[int, int]]) -> bytes:
    body = _uleb(len(local_groups))
    for count, valtype in local_groups:
        body += _uleb(count) + bytes([valtype])
    body += b"\x0b"  # the function body's `end` opcode
    return _uleb(len(body)) + body


def _code_section(*bodies: bytes) -> bytes:
    return _section(10, _uleb(len(bodies)) + b"".join(bodies))


def _subsection(sub_id: int, payload: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(payload)) + payload


def _namemap(entries: list[tuple[int, str]]) -> bytes:
    out = _uleb(len(entries))
    for index, text in entries:
        out += _uleb(index) + _name(text)
    return out


def _name_section(*subs: bytes) -> bytes:
    return _section(0, _name("name") + b"".join(subs))


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _functions(tmp_path: Path, data: bytes, **kwargs: object) -> dict:
    return WasmClient().functions(_write(tmp_path, data), **kwargs)  # type: ignore[arg-type]


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


def _mixed_module() -> bytes:
    """One imported func, three defined funcs, two exports, partial names.

    type 0 = (i32, i32) -> i32, type 1 = () -> (), type 2 = (f64) -> i64.
    func 0 is the import env.abort (type 1); funcs 1..3 are defined (types 1, 0,
    2). Exports: main -> func 1, encrypt -> func 2. The name section names only
    func 1 (real_main), so the other labels must fall back to the import field
    and the export name, and func 3 must stay unnamed.
    """
    return _module(
        _type_section(
            _functype([I32, I32], [I32]),  # type 0
            _functype([], []),  # type 1
            _functype([F64], [I64]),  # type 2
        ),
        _import_section(_import_func("env", "abort", 1)),  # func index 0
        _function_section(1, 0, 2),  # defined func indices 1, 2, 3
        _export_section(_export_func("main", 1), _export_func("encrypt", 2)),
        _code_section(
            _code_body([]),  # func 1: no locals
            _code_body([(3, I32)]),  # func 2: 3 i32 locals
            _code_body([(1, I64), (2, F64)]),  # func 3: 3 locals total
        ),
        _name_section(_subsection(1, _namemap([(1, "real_main")]))),
    )


def test_builds_the_whole_function_table_across_index_space(tmp_path: Path) -> None:
    """The headline: imports and defined funcs share one index space, in order.

    Func 0 is the import (its label falls back to the import field 'abort'); the
    defined funcs follow at 1..3. Each carries its resolved signature; a defined
    func also carries its code size and local count. main keeps its name-section
    name over the export; encrypt has no name-section entry so its label is the
    export name; func 3 is neither named nor exported and stays unlabelled --
    yet it still appears, which is the whole point over wasm.summary.
    """
    data = _functions(tmp_path, _mixed_module())

    assert data["module"] == "m.wasm"
    assert data["version"] == 1
    assert data["import_function_count"] == 1
    assert data["defined_function_count"] == 3
    assert data["has_name_section"] is True
    assert data["scan_capped"] is False
    assert data["total"] == 4
    assert data["count"] == 4
    assert data["offset"] == 0
    assert data["has_more"] is False

    fns = {f["index"]: f for f in data["functions"]}
    assert [f["index"] for f in data["functions"]] == [0, 1, 2, 3]

    imp = fns[0]
    assert imp["kind"] == "import"
    assert imp["name"] == "abort"  # no name-section entry -> import field
    assert imp["type_index"] == 1
    assert imp["signature"] == "() -> ()"
    assert imp["params"] == []
    assert imp["results"] == []
    assert imp["import_module"] == "env"
    assert imp["import_field"] == "abort"
    assert imp["exported"] is False
    assert "size" not in imp and "export_names" not in imp

    main = fns[1]
    assert main["kind"] == "local"
    assert main["name"] == "real_main"  # name section wins over the export name
    assert main["signature"] == "() -> ()"
    assert main["exported"] is True
    assert main["export_names"] == ["main"]
    assert main["size"] == 2  # _uleb(0) locals + end opcode
    assert main["locals"] == 0

    enc = fns[2]
    assert enc["name"] == "encrypt"  # no name-section entry -> export name
    assert enc["type_index"] == 0
    assert enc["signature"] == "(i32, i32) -> i32"
    assert enc["params"] == ["i32", "i32"]
    assert enc["results"] == ["i32"]
    assert enc["exported"] is True
    assert enc["locals"] == 3

    internal = fns[3]
    assert internal["name"] is None  # neither named nor exported
    assert internal["kind"] == "local"
    assert internal["signature"] == "(f64) -> i64"
    assert internal["exported"] is False
    assert internal["locals"] == 3
    assert internal["size"] == 6


def test_pagination_windows_the_table(tmp_path: Path) -> None:
    """offset/limit page the inventory, and has_more marks a filled page."""
    module = _module(
        _type_section(_functype([], [])),
        _function_section(0, 0, 0, 0, 0),  # five defined funcs, indices 0..4
        _code_section(*[_code_body([]) for _ in range(5)]),
    )
    data = _functions(tmp_path, module, offset=1, limit=2)
    assert data["total"] == 5
    assert data["count"] == 2
    assert data["offset"] == 1
    assert data["has_more"] is True
    assert [f["index"] for f in data["functions"]] == [1, 2]

    tail = _functions(tmp_path, module, offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False
    assert [f["index"] for f in tail["functions"]] == [4]


def test_scan_cap_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A module with more functions than the collect cap sets scan_capped."""
    monkeypatch.setattr(jsre_client, "_MAX_WASM_FUNCTIONS_COLLECT", 2)
    module = _module(
        _type_section(_functype([], [])),
        _function_section(0, 0, 0),
        _code_section(_code_body([]), _code_body([]), _code_body([])),
    )
    data = _functions(tmp_path, module)
    assert data["scan_capped"] is True
    assert data["total"] == 2  # only two materialised before the cap


def test_out_of_range_type_index_leaves_no_signature(tmp_path: Path) -> None:
    """A function whose type index is absent gets no signature, not a crash."""
    module = _module(
        _type_section(_functype([], [])),  # only type 0 exists
        _function_section(7),  # references a missing type
        _code_section(_code_body([])),
    )
    fn = _functions(tmp_path, module)["functions"][0]
    assert fn["type_index"] == 7
    assert "signature" not in fn
    assert "params" not in fn


def test_a_faulty_code_section_keeps_the_function_list(tmp_path: Path) -> None:
    """A code body that overruns is skipped, but the func still lists (no size).

    The Function section already named the defined function and its type; a
    malformed Code section must not lose it -- it just comes back without a size
    or local count, mirroring how the name reader keeps earlier subsections.
    """
    bad_code = _section(10, _uleb(1) + _uleb(200) + b"\x00")  # body_size 200, 1 byte
    module = _module(
        _type_section(_functype([I32], [])),
        _function_section(0),
        bad_code,
    )
    data = _functions(tmp_path, module)
    fn = data["functions"][0]
    assert fn["index"] == 0
    assert fn["signature"] == "(i32) -> ()"
    assert "size" not in fn and "locals" not in fn


def test_stripped_module_is_empty_not_an_error(tmp_path: Path) -> None:
    """A module with only a type table has no functions, and that is fine."""
    data = _functions(tmp_path, _module(_type_section(_functype([], []))))
    assert data["functions"] == []
    assert data["import_function_count"] == 0
    assert data["defined_function_count"] == 0
    assert data["has_name_section"] is False
    assert data["total"] == 0
    assert data["has_more"] is False


def test_needs_no_wabt(tmp_path: Path) -> None:
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    client._decompile = None
    assert client.available is False
    module = _module(
        _type_section(_functype([], [])),
        _function_section(0),
        _code_section(_code_body([])),
    )
    data = client.functions(_write(tmp_path, module))
    assert [f["index"] for f in data["functions"]] == [0]


def test_bad_magic_is_a_clean_backend_error(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        _functions(tmp_path, b"\x7fELF not a wasm module at all")
    assert excinfo.value.code == "backend_error"
    assert "WebAssembly" in excinfo.value.message


def test_section_overrun_is_a_clean_backend_error(tmp_path: Path) -> None:
    overrun = b"\x03" + _uleb(200) + b"\x00\x00"  # function section overruns module
    with pytest.raises(JsReError) as excinfo:
        _functions(tmp_path, _module(overrun))
    assert excinfo.value.code == "backend_error"
    assert "malformed" in excinfo.value.message


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().functions(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_service_wires_through(tmp_path: Path) -> None:
    """The service method returns the table under the wabt backend tag."""
    service = AnalysisService(Settings.load())
    path = _write(tmp_path, _mixed_module())
    result = service.wasm_functions(str(path))
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "wabt"
    assert result.data["defined_function_count"] == 3
    names = {f["index"]: f["name"] for f in result.data["functions"]}
    assert names[1] == "real_main"
    assert names[2] == "encrypt"


def test_docstring_frames_it_as_the_navigation_index() -> None:
    """The tool docstring must tell an agent this is the wasm function inventory."""
    doc = _tool_docstring("wasm.functions")
    for token in ("index", "signature", "import", "local", "has_more", "wasm.summary"):
        assert token in doc, token
