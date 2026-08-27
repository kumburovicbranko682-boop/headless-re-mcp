"""Unit tests for wasm.calls (pure-Python static call-graph extractor).

The instruction walker is exercised against hand-crafted code sections that mix
control flow (block/if/br_table), memory ops (memarg immediates), constants
(LEB and raw-byte immediates), prefixed opcodes (0xFC misc, 0xFD SIMD) and the
call family, so the immediate skipping stays aligned, calls are attributed to
the right function index, and an unknown opcode abandons only its own body.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_calls

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"


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


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _func_body(instrs: bytes, locals_: tuple[tuple[int, int], ...] = ()) -> bytes:
    decls = _uleb(len(locals_)) + b"".join(
        _uleb(count) + bytes([valtype]) for count, valtype in locals_
    )
    return decls + instrs + b"\x0b"  # the body's closing end opcode


def _code_section(*bodies: bytes) -> bytes:
    joined = b"".join(_uleb(len(body)) + body for body in bodies)
    return _section(10, _uleb(len(bodies)) + joined)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _func_import(module: str, field: str, typeidx: int = 0) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(typeidx)


def _import_section(*entries: bytes) -> bytes:
    return _section(2, _uleb(len(entries)) + b"".join(entries))


def _call(idx: int) -> bytes:
    return b"\x10" + _uleb(idx)


_CALL_INDIRECT = b"\x11\x00\x00"  # typeidx 0, tableidx 0


def _module(*sections: bytes) -> bytes:
    return _PREAMBLE + b"".join(sections)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_calls_collects_targets_and_counts(tmp_path: Path) -> None:
    body0 = _func_body(_call(1) + _call(1) + _CALL_INDIRECT)
    body1 = _func_body(b"")
    src = _write(tmp_path, _module(_code_section(body0, body1)))

    payload = parse_wasm_calls(src)

    assert payload["has_code_section"] is True
    assert payload["imported_count"] == 0
    assert payload["total"] == 2
    assert payload["functions"][0] == {
        "index": 0,
        "callees": [1],
        "callees_clipped": False,
        "call_sites": 2,
        "call_indirect_sites": 1,
        "decoded": True,
    }
    assert payload["functions"][1]["callees"] == []
    assert payload["functions"][1]["decoded"] is True
    assert payload["truncated"] is False


def test_wasm_calls_indices_start_after_imports(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module(
            _import_section(
                _func_import("env", "log"), _func_import("env", "abort")
            ),
            _code_section(_func_body(_call(0))),
        ),
    )

    payload = parse_wasm_calls(src)

    assert payload["imported_count"] == 2
    assert payload["functions"][0]["index"] == 2
    assert payload["functions"][0]["callees"] == [0]  # calls into the imports


def test_wasm_calls_walks_mixed_opcodes(tmp_path: Path) -> None:
    instrs = (
        b"\x02\x40"  # block (void blocktype)
        + b"\x41\x2a"  # i32.const 42
        + b"\x0d\x00"  # br_if 0
        + b"\x0b"  # end (block)
        + b"\x41\x00"  # i32.const 0
        + b"\x28\x02\x00"  # i32.load align=2 offset=0
        + b"\x21\x00"  # local.set 0
        + b"\x44" + b"\x00" * 8  # f64.const
        + b"\x1a"  # drop
        + b"\x0e\x02\x00\x01\x00"  # br_table [0, 1] default 0
        + b"\x20\x00"  # local.get 0
        + b"\xfc\x0b\x00"  # memory.fill (misc prefix)
        + b"\xfd\x0c" + b"\x00" * 16  # v128.const (SIMD prefix)
        + _call(1)
    )
    body = _func_body(instrs, locals_=((1, 0x7F),))
    src = _write(tmp_path, _module(_code_section(body, _func_body(b""))))

    payload = parse_wasm_calls(src)

    assert payload["functions"][0]["decoded"] is True
    assert payload["functions"][0]["callees"] == [1]
    assert payload["functions"][0]["call_sites"] == 1


def test_wasm_calls_unknown_opcode_abandons_only_that_body(tmp_path: Path) -> None:
    # 0xFB is the GC prefix, outside the walker's table; the call before it
    # is kept and the following body still decodes.
    bad = _func_body(_call(1) + b"\xfb\x00\x00")
    good = _func_body(_call(0))
    src = _write(tmp_path, _module(_code_section(bad, good)))

    payload = parse_wasm_calls(src)

    assert payload["functions"][0]["decoded"] is False
    assert payload["functions"][0]["callees"] == [1]
    assert payload["functions"][1]["decoded"] is True
    assert payload["functions"][1]["callees"] == [0]
    assert payload["truncated"] is False  # the section walk itself was fine


def test_wasm_calls_clips_callees(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_CALLEES", 2
    )
    body = _func_body(_call(3) + _call(1) + _call(2) + _call(1))
    src = _write(tmp_path, _module(_code_section(body)))

    row = parse_wasm_calls(src)["functions"][0]

    assert row["callees"] == [1, 2]  # sorted distinct, then clipped
    assert row["callees_clipped"] is True
    assert row["call_sites"] == 4


def test_wasm_calls_no_code_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module(_section(1, _uleb(0))))  # only a type section

    payload = parse_wasm_calls(src)

    assert payload["has_code_section"] is False
    assert payload["functions"] == []
    assert payload["total"] == 0


def test_wasm_calls_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_calls(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_calls_truncated_section_is_marked(tmp_path: Path) -> None:
    # The code section claims two bodies but provides one.
    body = _func_body(_call(1))
    section = _section(10, _uleb(2) + _uleb(len(body)) + body)
    src = _write(tmp_path, _module(section))

    payload = parse_wasm_calls(src)

    assert payload["truncated"] is True
    assert payload["total"] == 1
    assert payload["functions"][0]["callees"] == [1]


def test_wasm_calls_body_past_section_end_is_marked(tmp_path: Path) -> None:
    # A body that claims more bytes than the section holds.
    section = _section(10, _uleb(1) + _uleb(200) + b"\x00\x0b")
    src = _write(tmp_path, _module(section))

    payload = parse_wasm_calls(src)

    assert payload["truncated"] is True
    assert payload["total"] == 0


def test_wasm_calls_paginates(tmp_path: Path) -> None:
    bodies = [_func_body(_call(i)) for i in range(5)]
    src = _write(tmp_path, _module(_code_section(*bodies)))

    payload = parse_wasm_calls(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["index"] for r in payload["functions"]] == [2, 3]
    assert [r["callees"] for r in payload["functions"]] == [[2], [3]]


def test_wasm_calls_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_CALLS_COLLECT", 3
    )
    src = _write(
        tmp_path, _module(_code_section(*[_func_body(b"") for _ in range(10)]))
    )

    payload = parse_wasm_calls(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_calls_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_CALLS_PAGE", 2
    )
    src = _write(
        tmp_path, _module(_code_section(*[_func_body(b"") for _ in range(5)]))
    )

    payload = parse_wasm_calls(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_calls_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_calls(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_calls_refuses_oversized_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module(_code_section(_func_body(_call(0)))))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_calls(src)
    assert excinfo.value.code == "too_large"


def test_wasm_calls_docstring_names_shape() -> None:
    doc = parse_wasm_calls.__doc__ or ""
    assert "wabt-free" in doc
    assert "call graph" in doc
    assert "decoded" in doc
