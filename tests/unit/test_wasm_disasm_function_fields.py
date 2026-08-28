"""Tests for WasmClient.disasm_function, the single-function disassembler.

Like the other wasm tests these hand-build tiny modules (with real instruction
bytes in the Code section) so the decoder runs with no wabt. The decoder's
contract is that it is correct by construction: it knows each opcode's immediate
shape and stops cleanly at the first it does not, never guessing.
"""

from __future__ import annotations

import ast
import struct
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

I32 = 0x7F
I64 = 0x7E
F32 = 0x7D
F64 = 0x7C

# opcode bytes used below
LOCAL_GET = 0x20
LOCAL_TEE = 0x22
I32_CONST = 0x41
I64_CONST = 0x42
F32_CONST = 0x43
F64_CONST = 0x44
I32_ADD = 0x6A
I32_LOAD = 0x28
DROP = 0x1A
NOP = 0x01
CALL = 0x10
CALL_INDIRECT = 0x11
BR_TABLE = 0x0E
BLOCK = 0x02
IF = 0x04
ELSE = 0x05
END = 0x0B


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


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + (1).to_bytes(4, "little") + b"".join(sections)


def _functype(params: list[int], results: list[int]) -> bytes:
    return bytes([0x60]) + _uleb(len(params)) + bytes(params) + _uleb(len(results)) + bytes(results)


def _type_section(*functypes: bytes) -> bytes:
    return _section(1, _uleb(len(functypes)) + b"".join(functypes))


def _import_func(module: str, field: str, type_index: int) -> bytes:
    body = _name(module) + _name(field) + bytes([0x00]) + _uleb(type_index)
    return body


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _function_section(*type_indices: int) -> bytes:
    return _section(3, _uleb(len(type_indices)) + b"".join(_uleb(t) for t in type_indices))


def _locals(groups: list[tuple[int, int]]) -> bytes:
    out = _uleb(len(groups))
    for count, valtype in groups:
        out += _uleb(count) + bytes([valtype])
    return out


def _code_body(local_groups: list[tuple[int, int]], code: bytes) -> bytes:
    body = _locals(local_groups) + code
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


def _one_func(
    code: bytes,
    *,
    local_groups: list[tuple[int, int]] | None = None,
    params: list[int] | None = None,
    results: list[int] | None = None,
    name: str | None = None,
) -> bytes:
    sections = [
        _type_section(_functype(params or [I32, I32], results or [I32])),
        _function_section(0),
        _code_section(_code_body(local_groups or [], code)),
    ]
    if name is not None:
        sections.append(_name_section(_subsection(1, _namemap([(0, name)]))))
    return _module(*sections)


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _disasm(tmp_path: Path, data: bytes, **kwargs: object) -> dict:
    return WasmClient().disasm_function(_write(tmp_path, data), **kwargs)  # type: ignore[arg-type]


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


def test_decodes_a_defined_function_body(tmp_path: Path) -> None:
    """The headline: locals, ops, immediates and the closing end all come back.

    A three-op body (add two args, return) plus its declared local. The op
    offsets, mnemonics and structured immediates must all decode, the final end
    must sit at depth 0 as the function terminator, and decoded_all must be True.
    """
    code = (
        bytes([LOCAL_GET]) + _uleb(0)
        + bytes([LOCAL_GET]) + _uleb(1)
        + bytes([I32_ADD])
        + bytes([END])
    )
    data = _one_func(code, local_groups=[(1, I32)], name="mix")
    result = _disasm(tmp_path, data, index=0)

    assert result["name"] == "mix"
    assert result["kind"] == "local"
    assert result["has_code"] is True
    assert result["signature"] == "(i32, i32) -> i32"
    assert result["params"] == ["i32", "i32"]
    assert result["local_count"] == 1
    assert result["local_types"] == ["i32"]
    assert result["decoded_all"] is True
    assert result["total"] == 4
    assert result["count"] == 4
    assert result["has_more"] is False

    ops = result["ops"]
    assert [o["name"] for o in ops] == ["local.get", "local.get", "i32.add", "end"]
    assert ops[0]["opcode"] == "0x20"
    assert ops[0]["immediates"] == {"local_index": 0}
    assert ops[1]["text"] == "local.get 1"
    assert ops[2]["text"] == "i32.add"
    assert "immediates" not in ops[2]  # a NONE-shape op carries no immediates
    assert ops[3]["name"] == "end" and ops[3]["depth"] == 0
    # Offsets are strictly increasing and each op's bytes are disclosed.
    assert [o["offset"] for o in ops] == sorted(o["offset"] for o in ops)
    assert ops[0]["bytes"] == "2000"


def test_block_nesting_tracks_depth(tmp_path: Path) -> None:
    """block ... end raises the nesting depth for the ops inside it."""
    code = (
        bytes([BLOCK]) + bytes([0x40])  # block void
        + bytes([I32_CONST]) + _sleb(5)
        + bytes([DROP])
        + bytes([END])  # closes the block
        + bytes([END])  # closes the function
    )
    result = _disasm(tmp_path, _one_func(code, results=[]), index=0)
    ops = result["ops"]
    assert [o["name"] for o in ops] == ["block", "i32.const", "drop", "end", "end"]
    assert [o["depth"] for o in ops] == [0, 1, 1, 0, 0]
    assert ops[0]["immediates"] == {"blocktype": "void"}
    assert result["decoded_all"] is True


def test_if_else_blocktype(tmp_path: Path) -> None:
    """if renders its result blocktype, and the else keeps the same depth."""
    code = (
        bytes([IF]) + bytes([I32])  # if (result i32)
        + bytes([I32_CONST]) + _sleb(1)
        + bytes([ELSE])
        + bytes([I32_CONST]) + _sleb(0)
        + bytes([END])
        + bytes([END])
    )
    ops = _disasm(tmp_path, _one_func(code, params=[]), index=0)["ops"]
    assert [o["name"] for o in ops] == ["if", "i32.const", "else", "i32.const", "end", "end"]
    assert ops[0]["immediates"] == {"blocktype": "i32"}
    assert [o["depth"] for o in ops] == [0, 1, 1, 1, 0, 0]


def test_memarg_and_const_immediates(tmp_path: Path) -> None:
    """Loads carry align/offset; i32.const decodes a signed value."""
    code = (
        bytes([I32_CONST]) + _sleb(-5)
        + bytes([I32_LOAD]) + _uleb(2) + _uleb(16)
        + bytes([DROP])
        + bytes([END])
    )
    ops = _disasm(tmp_path, _one_func(code, params=[]), index=0)["ops"]
    assert ops[0]["name"] == "i32.const"
    assert ops[0]["immediates"] == {"value": -5}
    assert ops[1]["name"] == "i32.load"
    assert ops[1]["immediates"] == {"align": 2, "offset": 16}
    assert ops[1]["text"] == "i32.load align=2 offset=16"


def test_float_consts_decode(tmp_path: Path) -> None:
    """f32.const and f64.const read their raw little-endian bytes."""
    code = (
        bytes([F32_CONST]) + struct.pack("<f", 1.5)
        + bytes([DROP])
        + bytes([F64_CONST]) + struct.pack("<d", 2.25)
        + bytes([DROP])
        + bytes([END])
    )
    ops = _disasm(tmp_path, _one_func(code, params=[], results=[]), index=0)["ops"]
    assert ops[0]["name"] == "f32.const"
    assert ops[0]["immediates"]["value"] == pytest.approx(1.5)
    assert ops[2]["name"] == "f64.const"
    assert ops[2]["immediates"]["value"] == pytest.approx(2.25)


def test_br_table_and_call_indirect(tmp_path: Path) -> None:
    """br_table lists its targets + default; call_indirect its type/table."""
    code = (
        bytes([BR_TABLE]) + _uleb(2) + _uleb(0) + _uleb(1) + _uleb(3)  # targets 0,1 default 3
        + bytes([CALL_INDIRECT]) + _uleb(0) + _uleb(0)
        + bytes([END])
    )
    ops = _disasm(tmp_path, _one_func(code, params=[], results=[]), index=0)["ops"]
    assert ops[0]["name"] == "br_table"
    assert ops[0]["immediates"] == {"targets": [0, 1], "default": 3}
    assert ops[1]["name"] == "call_indirect"
    assert ops[1]["immediates"] == {"type_index": 0, "table_index": 0}


def test_fc_prefixed_ops_decode(tmp_path: Path) -> None:
    """The 0xFC family decodes: a no-operand trunc_sat and a two-index copy."""
    code = (
        bytes([0xFC]) + _uleb(0)  # i32.trunc_sat_f32_s (no operands)
        + bytes([0xFC]) + _uleb(10) + _uleb(0) + _uleb(0)  # memory.copy
        + bytes([END])
    )
    ops = _disasm(tmp_path, _one_func(code, params=[], results=[]), index=0)["ops"]
    assert ops[0]["name"] == "i32.trunc_sat_f32_s"
    assert ops[0]["opcode"] == "0xfc 0"
    assert "immediates" not in ops[0]
    assert ops[1]["name"] == "memory.copy"
    assert ops[1]["opcode"] == "0xfc 10"
    assert ops[1]["immediates"] == {"operands": [0, 0]}


def test_simd_prefix_stops_the_walk_cleanly(tmp_path: Path) -> None:
    """A 0xFD (SIMD) op stops decoding, disclosed, keeping the ops before it.

    The decoder never guesses an unknown immediate shape. It emits every op up
    to the SIMD one, then reports decoded_all False with the exact byte offset
    and opcode it stopped on -- an honest partial listing, never garbage.
    """
    code = (
        bytes([I32_CONST]) + _sleb(1)
        + bytes([0xFD]) + _uleb(0)  # v128 op -- unknown shape here
        + bytes([END])
    )
    result = _disasm(tmp_path, _one_func(code, params=[], results=[I32]), index=0)
    assert [o["name"] for o in result["ops"]] == ["i32.const"]
    assert result["decoded_all"] is False
    assert result["stopped_opcode"] == "0xfd"
    # The stop offset is the byte position of the 0xFD op (after i32.const 1).
    assert result["stopped_at_offset"] == result["ops"][0]["offset"] + 2


def test_unknown_opcode_stops_the_walk(tmp_path: Path) -> None:
    """A reserved/unknown opcode byte stops the walk, disclosed."""
    code = bytes([NOP]) + bytes([0x06]) + bytes([END])  # 0x06 is reserved
    result = _disasm(tmp_path, _one_func(code, params=[], results=[]), index=0)
    assert [o["name"] for o in result["ops"]] == ["nop"]
    assert result["decoded_all"] is False
    assert result["stopped_opcode"] == "0x06"


def test_imported_function_has_no_body(tmp_path: Path) -> None:
    """An imported function resolves its signature but has no code."""
    data = _module(
        _type_section(_functype([I32], [I32]), _functype([], [])),
        _import_section(_import_func("env", "host", 0)),
        _function_section(1),
        _code_section(_code_body([], bytes([END]))),
        _name_section(_subsection(1, _namemap([(0, "host"), (1, "main")]))),
    )
    imp = _disasm(tmp_path, data, index=0)
    assert imp["kind"] == "import"
    assert imp["has_code"] is False
    assert imp["ops"] == []
    assert imp["signature"] == "(i32) -> i32"
    assert imp["name"] == "host"
    assert imp["decoded_all"] is True
    # The defined func that follows the import decodes normally.
    main = _disasm(tmp_path, data, index=1)
    assert main["kind"] == "local"
    assert main["name"] == "main"
    assert [o["name"] for o in main["ops"]] == ["end"]


def test_out_of_range_and_negative_index_are_invalid_params(tmp_path: Path) -> None:
    data = _one_func(bytes([END]), params=[], results=[])
    path = _write(tmp_path, data)
    with pytest.raises(JsReError) as oor:
        WasmClient().disasm_function(path, index=99)
    assert oor.value.code == "invalid_params"
    assert "out of range" in oor.value.message
    with pytest.raises(JsReError) as neg:
        WasmClient().disasm_function(path, index=-1)
    assert neg.value.code == "invalid_params"


def test_pagination_windows_the_ops(tmp_path: Path) -> None:
    code = bytes([NOP]) * 10 + bytes([END])  # 11 ops total
    data = _one_func(code, params=[], results=[])
    page = _disasm(tmp_path, data, index=0, offset=2, limit=3)
    assert page["total"] == 11
    assert page["count"] == 3
    assert page["offset"] == 2
    assert page["has_more"] is True
    assert all(o["name"] == "nop" for o in page["ops"])


def test_scan_cap_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_OPS_COLLECT", 3)
    code = bytes([NOP]) * 10 + bytes([END])
    result = _disasm(tmp_path, _one_func(code, params=[], results=[]), index=0)
    assert result["scan_capped"] is True
    assert result["total"] == 3  # only three ops materialised before the cap


def test_bad_magic_is_a_clean_backend_error(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        _disasm(tmp_path, b"\x7fELF not wasm", index=0)
    assert excinfo.value.code == "backend_error"


def test_section_overrun_is_a_clean_backend_error(tmp_path: Path) -> None:
    overrun = b"\x03" + _uleb(200) + b"\x00\x00"  # function section overruns module
    with pytest.raises(JsReError) as excinfo:
        _disasm(tmp_path, _module(overrun), index=0)
    assert excinfo.value.code == "backend_error"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().disasm_function(tmp_path / "nope.wasm", index=0)
    assert excinfo.value.code == "not_found"


def test_needs_no_wabt(tmp_path: Path) -> None:
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    client._decompile = None
    assert client.available is False
    code = bytes([I32_CONST]) + _sleb(42) + bytes([END])
    result = client.disasm_function(_write(tmp_path, _one_func(code, params=[])), index=0)
    assert result["ops"][0]["text"] == "i32.const 42"


def test_service_wires_through(tmp_path: Path) -> None:
    service = AnalysisService(Settings.load())
    code = bytes([LOCAL_GET]) + _uleb(0) + bytes([END])
    path = _write(tmp_path, _one_func(code, name="only"))
    result = service.wasm_disasm_function(str(path), 0)
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "wabt"
    assert result.data["name"] == "only"
    assert result.data["ops"][0]["name"] == "local.get"


def test_docstring_frames_it_as_the_reverse_of_the_whole_module(tmp_path: Path) -> None:
    doc = _tool_docstring("wasm.disasm_function")
    for token in ("wasm.functions", "decoded_all", "immediates", "has_code", "opcode"):
        assert token in doc, token
