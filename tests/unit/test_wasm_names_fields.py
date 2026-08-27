"""Unit tests for wasm.names (pure-Python, wabt-free name-section parser).

The parser is exercised against hand-crafted .wasm binaries carrying a "name"
custom section, so the custom-section discovery, the subsection walk, the
module/function name maps, the local-name skip, and the truncated/stripped
degradation are all really executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_names

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


def _name(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _uleb(len(encoded)) + encoded


def _namemap(pairs: list[tuple[int, str]]) -> bytes:
    out = _uleb(len(pairs))
    for idx, name in pairs:
        out += _uleb(idx) + _name(name)
    return out


def _subsection(sub_id: int, content: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(content)) + content


def _sub_module(name: str) -> bytes:
    return _subsection(0, _name(name))


def _sub_functions(pairs: list[tuple[int, str]]) -> bytes:
    return _subsection(1, _namemap(pairs))


def _sub_locals_empty() -> bytes:
    # Local-name subsection (id 2): an empty indirectnamemap; must be skipped.
    return _subsection(2, _uleb(0))


def _custom(name: str, extra: bytes = b"") -> bytes:
    body = _name(name) + extra
    return bytes([0]) + _uleb(len(body)) + body


def _name_section_bytes(*subs: bytes) -> bytes:
    body = _name("name") + b"".join(subs)
    return bytes([0]) + _uleb(len(body)) + body


def _module_with_names(*subs: bytes) -> bytes:
    return _PREAMBLE + _name_section_bytes(*subs)


def _write(tmp_path: Path, data: bytes, name: str = "mod.wasm") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_wasm_names_recovers_function_names(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module_with_names(
            _sub_functions([(0, "_start"), (3, "_malloc"), (7, "main")])
        ),
    )

    payload = parse_wasm_names(src)

    assert payload["has_name_section"] is True
    assert payload["module"] is None
    assert payload["functions"] == [
        {"index": 0, "name": "_start"},
        {"index": 3, "name": "_malloc"},
        {"index": 7, "name": "main"},
    ]
    assert payload["total"] == 3
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_wasm_names_reads_module_name(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module_with_names(_sub_module("my_module"), _sub_functions([(0, "main")])),
    )

    payload = parse_wasm_names(src)

    assert payload["module"] == "my_module"
    assert payload["functions"] == [{"index": 0, "name": "main"}]


def test_wasm_names_stripped_module_has_no_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _PREAMBLE)

    payload = parse_wasm_names(src)

    assert payload["has_name_section"] is False
    assert payload["module"] is None
    assert payload["functions"] == []
    assert payload["total"] == 0
    assert payload["truncated"] is False


def test_wasm_names_other_custom_section_is_not_name(tmp_path: Path) -> None:
    src = _write(tmp_path, _PREAMBLE + _custom("producers", b"\x01\x02"))

    payload = parse_wasm_names(src)

    assert payload["has_name_section"] is False


def test_wasm_names_module_only_section(tmp_path: Path) -> None:
    src = _write(tmp_path, _module_with_names(_sub_module("only_mod")))

    payload = parse_wasm_names(src)

    assert payload["has_name_section"] is True
    assert payload["module"] == "only_mod"
    assert payload["functions"] == []
    assert payload["total"] == 0


def test_wasm_names_skips_local_name_subsection(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module_with_names(_sub_functions([(1, "f")]), _sub_locals_empty()),
    )

    payload = parse_wasm_names(src)

    assert payload["functions"] == [{"index": 1, "name": "f"}]


def test_wasm_names_skips_non_name_custom_before_name(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _PREAMBLE
        + _custom("producers", b"\xaa")
        + _name_section_bytes(_sub_functions([(2, "g")])),
    )

    payload = parse_wasm_names(src)

    assert payload["has_name_section"] is True
    assert payload["functions"] == [{"index": 2, "name": "g"}]


def test_wasm_names_not_a_module(tmp_path: Path) -> None:
    src = _write(tmp_path, b"not wasm", name="x.bin")

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_names(src)
    assert excinfo.value.code == "invalid_params"


def test_wasm_names_partial_namemap_returns_what_it_read(tmp_path: Path) -> None:
    # The namemap claims 3 entries but supplies only 1; the parse keeps that one
    # and flags truncated instead of inventing the rest.
    content = _uleb(3) + _uleb(0) + _name("a")
    src = _write(tmp_path, _module_with_names(_subsection(1, content)))

    payload = parse_wasm_names(src)

    assert payload["functions"] == [{"index": 0, "name": "a"}]
    assert payload["truncated"] is True


def test_wasm_names_subsection_size_past_section_is_marked(tmp_path: Path) -> None:
    # A function subsection declares a 50-byte body but only 1 byte follows.
    body = _name("name") + bytes([1]) + _uleb(50) + b"\x01"
    section = bytes([0]) + _uleb(len(body)) + body
    src = _write(tmp_path, _PREAMBLE + section)

    payload = parse_wasm_names(src)

    assert payload["has_name_section"] is True
    assert payload["functions"] == []
    assert payload["truncated"] is True


def test_wasm_names_paginates(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        _module_with_names(_sub_functions([(i, f"f{i:03d}") for i in range(5)])),
    )

    payload = parse_wasm_names(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [r["name"] for r in payload["functions"]] == ["f002", "f003"]


def test_wasm_names_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_NAMES_COLLECT", 3
    )
    src = _write(
        tmp_path,
        _module_with_names(_sub_functions([(i, f"f{i:03d}") for i in range(10)])),
    )

    payload = parse_wasm_names(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_wasm_names_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_WASM_NAMES_PAGE", 2
    )
    src = _write(
        tmp_path,
        _module_with_names(_sub_functions([(i, f"f{i:03d}") for i in range(5)])),
    )

    payload = parse_wasm_names(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_wasm_names_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        parse_wasm_names(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_wasm_names_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    src = _write(tmp_path, _module_with_names(_sub_functions([(0, "main")])))

    with pytest.raises(JsReError) as excinfo:
        parse_wasm_names(src)
    assert excinfo.value.code == "too_large"


def test_wasm_names_docstring_names_shape() -> None:
    doc = parse_wasm_names.__doc__ or ""
    assert "wabt-free" in doc
    assert "truncated" in doc
