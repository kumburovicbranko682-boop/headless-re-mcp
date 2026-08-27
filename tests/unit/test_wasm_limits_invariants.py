"""Cross-tool limits and pagination invariants for the wabt-free wasm.* suite.

The per-tool unit tests exercise each parser's collect cap by monkeypatching it
down to a tiny value, and test_wasm_suite_integration.py checks that the tools
agree about one coherent module. Neither locks the contract this file covers:

* every paginated wasm.* result exposes the same envelope -- count / total /
  offset / has_more / scan_capped / truncated -- with the same (exact) types
  and the same has_more arithmetic, so a future tool or an edit to an existing
  one cannot quietly drift from the pagination contract;
* the window parameters behave identically everywhere: limit=1 serves at most
  one row, and an offset past the end serves an empty page that never claims
  has_more;
* the instruction walker is iterative, so a body with tens of thousands of
  nested blocks -- which would overflow Python's default recursion limit in a
  recursive design -- and a very long straight-line instruction stream both
  decode cleanly;
* the real default collect caps (not a monkeypatched stand-in) actually apply
  when a module crosses them, so a typo in the constant or a cap that is
  wired in the tiny-value test but skipped at scale cannot ship.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    parse_wasm_callers,
    parse_wasm_calls,
    parse_wasm_data,
    parse_wasm_elements,
    parse_wasm_exports,
    parse_wasm_features,
    parse_wasm_functions,
    parse_wasm_globals,
    parse_wasm_imports,
    parse_wasm_memory,
    parse_wasm_names,
    parse_wasm_producers,
    parse_wasm_sections,
    parse_wasm_strings,
    parse_wasm_tables,
)
from tests.unit.test_wasm_suite_integration import _build_module

_PREAMBLE = b"\x00asm\x01\x00\x00\x00"

# Every paginated wasm.* parser: (parser, the key holding its row list, extra
# call kwargs beyond path). parse_wasm_start is scalar (no row list) and the
# two wabt-backed tools shell out, so none of the three belongs here.
_PAGINATED: tuple[tuple[Callable[..., dict[str, Any]], str, dict[str, int]], ...] = (
    (parse_wasm_imports, "imports", {}),
    (parse_wasm_exports, "exports", {}),
    (parse_wasm_sections, "sections", {}),
    (parse_wasm_names, "functions", {}),
    (parse_wasm_functions, "functions", {}),
    (parse_wasm_strings, "strings", {}),
    (parse_wasm_globals, "globals", {}),
    (parse_wasm_data, "segments", {}),
    (parse_wasm_elements, "entries", {}),
    (parse_wasm_memory, "memories", {}),
    (parse_wasm_tables, "tables", {}),
    (parse_wasm_calls, "functions", {}),
    (parse_wasm_callers, "callers", {"function": 0}),
    (parse_wasm_producers, "producers", {}),
    (parse_wasm_features, "features", {}),
)

# The shared pagination envelope: field -> exact type. bool is checked with
# `type(...) is`, so an int sneaking in where a bool belongs (or vice versa --
# bool subclasses int) fails rather than passing by coercion.
_ENVELOPE_TYPES: dict[str, type] = {
    "count": int,
    "total": int,
    "offset": int,
    "has_more": bool,
    "scan_capped": bool,
    "truncated": bool,
}


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


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _code_only_module(instructions: bytes) -> bytes:
    """A module whose sole content is one function body (no locals)."""
    body = _uleb(0) + instructions + b"\x0b"
    code = _uleb(1) + _uleb(len(body)) + body
    return _PREAMBLE + _section(10, code)


@pytest.fixture()
def module_path(tmp_path: Path) -> Path:
    target = tmp_path / "everything.wasm"
    target.write_bytes(_build_module())
    return target


def test_every_paginated_tool_shares_the_envelope(module_path: Path) -> None:
    for parser, list_key, extra in _PAGINATED:
        result = parser(module_path, **extra)
        for field, exact_type in _ENVELOPE_TYPES.items():
            assert field in result, f"{parser.__name__} lacks {field!r}"
            assert type(result[field]) is exact_type, (
                f"{parser.__name__}[{field!r}] is {type(result[field]).__name__},"
                f" expected {exact_type.__name__}"
            )
        rows = result[list_key]
        assert isinstance(rows, list), f"{parser.__name__}[{list_key!r}]"
        assert result["count"] == len(rows), parser.__name__
        assert result["offset"] == 0, parser.__name__
        assert result["total"] >= result["count"], parser.__name__
        assert result["has_more"] == (result["count"] < result["total"]), parser.__name__


def test_window_parameters_behave_identically_everywhere(
    module_path: Path,
) -> None:
    for parser, list_key, extra in _PAGINATED:
        first = parser(module_path, limit=1, **extra)
        assert first["count"] == len(first[list_key]) <= 1, parser.__name__
        assert first["has_more"] == (first["total"] > 1), parser.__name__

        beyond = parser(module_path, offset=10**9, **extra)
        assert beyond[list_key] == [], parser.__name__
        assert beyond["count"] == 0, parser.__name__
        assert beyond["has_more"] is False, parser.__name__
        assert beyond["total"] == first["total"], parser.__name__


def test_deep_block_nesting_decodes_without_recursion(tmp_path: Path) -> None:
    # 20000 alternating block/loop openers, a call at the bottom, 20000 ends.
    # A recursive walker would overflow Python's default ~1000-frame stack;
    # the iterative one must decode it fully and still find the call.
    depth = 20_000
    instructions = (
        b"\x02\x40\x03\x40" * (depth // 2)  # block void / loop void, nested
        + b"\x10\x00"  # call 0 (this same function; the walker is index-blind)
        + b"\x0b" * depth
    )
    target = tmp_path / "deep.wasm"
    target.write_bytes(_code_only_module(instructions))

    result = parse_wasm_calls(target)
    assert result["truncated"] is False
    assert result["functions"] == [
        {
            "index": 0,
            "callees": [0],
            "callees_clipped": False,
            "call_sites": 1,
            "call_indirect_sites": 0,
            "decoded": True,
        }
    ]

    xrefs = parse_wasm_callers(target, function=0)
    assert xrefs["total"] == 1
    assert xrefs["callers"] == [{"index": 0, "call_sites": 1, "decoded": True}]
    assert xrefs["undecoded_bodies"] == 0


def test_long_straight_line_stream_decodes(tmp_path: Path) -> None:
    # 100k (i32.const 0; drop) pairs: a 300 KB body with no structure at all,
    # the shape a large -O0 build or an obfuscator produces.
    instructions = b"\x41\x00\x1a" * 100_000
    target = tmp_path / "long.wasm"
    target.write_bytes(_code_only_module(instructions))

    result = parse_wasm_calls(target)
    row = result["functions"][0]
    assert row["decoded"] is True
    assert row["callees"] == []
    assert row["call_sites"] == 0
    assert row["call_indirect_sites"] == 0
    assert result["truncated"] is False


def test_default_import_cap_applies_at_real_scale(tmp_path: Path) -> None:
    # The per-tool tests monkeypatch the cap down to 3; this is the one place
    # the shipped default is crossed for real.
    cap = jsre_client._MAX_WASM_IMPORTS_COLLECT
    entry = _uleb(1) + b"m" + _uleb(1) + b"f" + b"\x00" + _uleb(0)
    imports = _uleb(cap + 1) + entry * (cap + 1)
    target = tmp_path / "imports.wasm"
    target.write_bytes(_PREAMBLE + _section(2, imports))

    result = parse_wasm_imports(target)
    assert result["total"] == cap
    assert result["scan_capped"] is True
    assert result["has_more"] is True
    assert result["truncated"] is False


def test_default_function_cap_applies_at_real_scale(tmp_path: Path) -> None:
    cap = jsre_client._MAX_WASM_FUNCTIONS_COLLECT
    types = _uleb(1) + b"\x60" + _uleb(0) + _uleb(0)  # type 0: [] -> []
    funcs = _uleb(cap + 1) + b"\x00" * (cap + 1)  # every function is type 0
    target = tmp_path / "functions.wasm"
    target.write_bytes(_PREAMBLE + _section(1, types) + _section(3, funcs))

    result = parse_wasm_functions(target)
    assert result["total"] == cap
    assert result["scan_capped"] is True
    assert result["has_more"] is True
    assert result["truncated"] is False
