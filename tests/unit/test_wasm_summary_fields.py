"""wasm.summary: a node-free one-call profile of a WebAssembly module.

Where the per-kind parsers each drill into one section, this walks the module
once and rolls their headline counts into a single overview. These tests pin the
contract on hand-assembled modules: the full roll-up against the shared
integration module (so the counts are checked against the same bytes the other
tools read), the imported-vs-defined split across every kind, an empty module,
truncation on a short section, and the non-wasm / not_found / too_large guards.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, parse_wasm_summary
from tests.unit.test_wasm_suite_integration import _build_module

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
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(body)) + body


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _write(tmp_path: Path, raw: bytes) -> Path:
    target = tmp_path / "m.wasm"
    target.write_bytes(raw)
    return target


def test_summary_rolls_up_the_integration_module(tmp_path: Path) -> None:
    payload = parse_wasm_summary(_write(tmp_path, _build_module()))
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False
    assert payload["types"] == 2

    assert payload["imports"] == {"total": 2, "func": 1, "table": 0, "memory": 0, "global": 1}
    assert payload["exports"] == {"total": 4, "func": 1, "table": 1, "memory": 1, "global": 1}

    assert payload["functions"] == {"imported": 1, "defined": 2, "total": 3}
    assert payload["tables"] == {"imported": 0, "defined": 1, "total": 1}
    assert payload["memories"] == {"imported": 0, "defined": 1, "total": 1}
    assert payload["globals"] == {"imported": 1, "defined": 1, "total": 2}

    assert payload["element_segments"] == 1
    assert payload["data_segments"] == 1
    assert payload["start"] == {"present": True, "function": 1}

    assert payload["custom_sections"] == {
        "total": 3,
        "names": ["name", "producers", "target_features"],
    }
    assert payload["has_name_section"] is True
    assert payload["sections"] == [
        "type",
        "import",
        "function",
        "table",
        "memory",
        "global",
        "export",
        "start",
        "element",
        "code",
        "data",
        "custom",
        "custom",
        "custom",
    ]
    assert payload["input_bytes"] > 0


def test_imported_entries_count_toward_every_kind(tmp_path: Path) -> None:
    # An import-only module with one import of each external kind: the summary
    # must credit each to the imported side of its kind, defined staying zero.
    imports = _section(
        2,
        _vec(
            [
                _name("env") + _name("f") + b"\x00" + _uleb(0),
                _name("env") + _name("t") + b"\x01" + b"\x70" + b"\x00" + _uleb(1),
                _name("env") + _name("m") + b"\x02" + b"\x00" + _uleb(1),
                _name("env") + _name("g") + b"\x03" + b"\x7f" + b"\x00",
            ]
        ),
    )
    payload = parse_wasm_summary(_write(tmp_path, _PREAMBLE + imports))
    assert payload["imports"] == {"total": 4, "func": 1, "table": 1, "memory": 1, "global": 1}
    assert payload["functions"] == {"imported": 1, "defined": 0, "total": 1}
    assert payload["tables"] == {"imported": 1, "defined": 0, "total": 1}
    assert payload["memories"] == {"imported": 1, "defined": 0, "total": 1}
    assert payload["globals"] == {"imported": 1, "defined": 0, "total": 1}
    assert payload["truncated"] is False


def test_empty_module_is_all_zero(tmp_path: Path) -> None:
    payload = parse_wasm_summary(_write(tmp_path, _PREAMBLE))
    assert payload["types"] == 0
    assert payload["imports"] == {"total": 0, "func": 0, "table": 0, "memory": 0, "global": 0}
    assert payload["functions"] == {"imported": 0, "defined": 0, "total": 0}
    assert payload["element_segments"] == 0
    assert payload["data_segments"] == 0
    assert payload["start"] == {"present": False, "function": None}
    assert payload["custom_sections"] == {"total": 0, "names": []}
    assert payload["has_name_section"] is False
    assert payload["sections"] == []
    assert payload["truncated"] is False


def test_short_section_sets_truncated_but_keeps_earlier_counts(tmp_path: Path) -> None:
    # A valid function section, then an export header claiming a body that runs
    # past the file: the walk stops, functions.defined stands, truncated flips.
    good = _section(3, _vec([_uleb(0), _uleb(1)]))
    short = bytes([7]) + _uleb(99)  # export section, 99-byte body, no bytes follow
    payload = parse_wasm_summary(_write(tmp_path, _PREAMBLE + good + short))
    assert payload["functions"]["defined"] == 2
    assert payload["truncated"] is True
    assert payload["exports"]["total"] == 0


def test_non_wasm_is_invalid_params(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_summary(_write(tmp_path, b"not a wasm module at all"))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        parse_wasm_summary(tmp_path / "nope.wasm")
    assert info.value.code == "not_found"


def test_oversized_input_is_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    with pytest.raises(JsReError) as info:
        parse_wasm_summary(_write(tmp_path, _build_module()))
    assert info.value.code == "too_large"
