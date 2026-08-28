"""wasm.disassemble decodes one defined function's instruction stream."""

from __future__ import annotations

import ast
import struct
from pathlib import Path

from headless_re_mcp.backends.jsre.client import WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import list_wasm_disassemble
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


def _name_bytes(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _code_entry(local_groups: list[tuple[int, int]], instrs: bytes) -> bytes:
    body = _uleb(len(local_groups))
    for count, valtype in local_groups:
        body += _uleb(count) + bytes([valtype])
    body += instrs
    return _uleb(len(body)) + body


def _code_section(entries: list[bytes]) -> bytes:
    return _section(10, _uleb(len(entries)) + b"".join(entries))


def _import_func(module: str, name: str, type_index: int) -> bytes:
    return _name_bytes(module) + _name_bytes(name) + b"\x00" + _uleb(type_index)


def _import_section(entries: list[bytes]) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _name_section(func_names: dict[int, str]) -> bytes:
    body = _uleb(len(func_names))
    for index, text in func_names.items():
        body += _uleb(index) + _name_bytes(text)
    subsection = bytes([1]) + _uleb(len(body)) + body
    payload = _name_bytes("name") + subsection
    return _section(0, payload)


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


def test_disassemble_decodes_a_simple_body() -> None:
    # local.get 0 ; i32.const 42 ; i32.add ; end
    instrs = bytes([0x20, 0x00, 0x41, 0x2A, 0x6A, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0)
    assert result["found"] is True
    assert result["imported"] is False
    assert result["complete"] is True
    assert result["stopped_reason"] is None
    assert result["total"] == 4
    ops = [(i["op"], i["operands"]) for i in result["instructions"]]
    assert ops == [
        ("local.get", ["0"]),
        ("i32.const", ["42"]),
        ("i32.add", []),
        ("end", []),
    ]
    assert result["instructions"][0]["offset"] == 0
    assert result["instructions"][1]["offset"] == 2


def test_disassemble_reads_memarg_and_call() -> None:
    # i32.load align=2 offset=16 ; call 3 ; end
    instrs = bytes([0x28, 0x02, 0x10, 0x10, 0x03, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0)
    by_op = {i["op"]: i for i in result["instructions"]}
    assert by_op["i32.load"]["operands"] == ["align=2", "offset=16"]
    assert by_op["call"]["operands"] == ["func 3"]


def test_disassemble_reads_br_table_and_blocktype() -> None:
    # block () ; br_table [0,1] default 2 ; end ; end
    instrs = bytes([0x02, 0x40, 0x0E, 0x02, 0x00, 0x01, 0x02, 0x0B, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0)
    by_op = {i["op"]: i for i in result["instructions"]}
    assert by_op["block"]["operands"] == ["()"]
    assert by_op["br_table"]["operands"] == ["0", "1", "default 2"]


def test_disassemble_renders_f32_const() -> None:
    instrs = bytes([0x43]) + struct.pack("<f", 1.5) + bytes([0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0)
    assert result["instructions"][0]["op"] == "f32.const"
    assert result["instructions"][0]["operands"] == ["1.5"]


def test_disassemble_stops_cleanly_on_simd() -> None:
    # i32.const 1 ; <0xfd simd> ; end -- decode stops at the SIMD prefix.
    instrs = bytes([0x41, 0x01, 0xFD, 0x00, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0)
    assert result["total"] == 1
    assert result["complete"] is False
    assert result["stopped_reason"] == "unsupported_opcode:0xfd"


def test_disassemble_decodes_fc_prefix_bulk_memory() -> None:
    # memory.fill (0xfc 11, reserved 0x00) ; end
    instrs = bytes([0xFC, 0x0B, 0x00, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0)
    assert result["instructions"][0]["op"] == "memory.fill"
    assert result["complete"] is True


def test_disassemble_reports_imported_index() -> None:
    module = _module(
        _import_section([_import_func("env", "host", 0)]),
        _code_section([_code_entry([], bytes([0x0B]))]),
    )
    imported = list_wasm_disassemble(module, function=0)
    assert imported["imported"] is True
    assert imported["found"] is False
    # Function 1 is the first defined body.
    defined = list_wasm_disassemble(module, function=1)
    assert defined["found"] is True


def test_disassemble_out_of_range_is_not_found() -> None:
    module = _module(_code_section([_code_entry([], bytes([0x0B]))]))
    result = list_wasm_disassemble(module, function=9)
    assert result["found"] is False
    assert result["imported"] is False


def test_disassemble_picks_up_the_debug_name() -> None:
    module = _module(
        _code_section([_code_entry([], bytes([0x0B]))]),
        _name_section({0: "handle_message"}),
    )
    result = list_wasm_disassemble(module, function=0)
    assert result["name"] == "handle_message"


def test_disassemble_pages_the_instructions() -> None:
    # nop x5 ; end
    instrs = bytes([0x01, 0x01, 0x01, 0x01, 0x01, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    result = list_wasm_disassemble(module, function=0, offset=0, limit=2)
    assert result["count"] == 2
    assert result["total"] == 6
    assert result["has_more"] is True


def test_disassemble_through_the_client(tmp_path: Path) -> None:
    instrs = bytes([0x20, 0x00, 0x0B])
    module = _module(_code_section([_code_entry([], instrs)]))
    wasm = tmp_path / "m.wasm"
    wasm.write_bytes(module)
    result = WasmClient().disassemble(wasm, function=0)
    assert result["found"] is True
    assert result["instructions"][0]["op"] == "local.get"


def test_wasm_disassemble_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.disassemble")
    assert "instructions" in doc
    assert "stopped_reason" in doc
    assert "operands" in doc
    assert "imported" in doc
