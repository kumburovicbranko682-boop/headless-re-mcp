"""Tests for WasmClient.names, the ``name`` custom section symbol reader.

Like the summary tests these hand-build tiny modules so the parser runs on a box
with no wabt: the whole point of wasm.names is that it reads the binary directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsReError, WasmClient


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


def _namemap(entries: list[tuple[int, str]]) -> bytes:
    out = _uleb(len(entries))
    for index, text in entries:
        out += _uleb(index) + _name(text)
    return out


def _local_map(funcs: list[tuple[int, list[tuple[int, str]]]]) -> bytes:
    out = _uleb(len(funcs))
    for func_index, locals_ in funcs:
        out += _uleb(func_index) + _uleb(len(locals_))
        for local_index, text in locals_:
            out += _uleb(local_index) + _name(text)
    return out


def _subsection(sub_id: int, payload: bytes) -> bytes:
    return bytes([sub_id]) + _uleb(len(payload)) + payload


def _name_section(*subs: bytes) -> bytes:
    return _section(0, _name("name") + b"".join(subs))


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _names(tmp_path: Path, data: bytes) -> dict:
    return WasmClient().names(_write(tmp_path, data))


def test_recovers_module_function_local_and_global_names(tmp_path: Path) -> None:
    """The headline case: a full name section maps indices back to identifiers."""
    section = _name_section(
        _subsection(0, _name("my_module")),
        # Deliberately out of index order so the sort is exercised.
        _subsection(1, _namemap([(0, "malloc"), (2, "main"), (1, "free")])),
        _subsection(2, _local_map([(0, [(0, "argc"), (1, "count")])])),
        _subsection(7, _namemap([(0, "heap_base"), (1, "stack_ptr")])),
    )
    data = _names(tmp_path, _module(section))

    assert data["module"] == "m.wasm"
    assert data["version"] == 1
    assert data["has_name_section"] is True
    assert data["module_name"] == "my_module"
    assert data["functions"] == [
        {"index": 0, "name": "malloc"},
        {"index": 1, "name": "free"},
        {"index": 2, "name": "main"},
    ]
    assert data["function_count"] == 3
    assert data["locals"] == [
        {"function": 0, "index": 0, "name": "argc"},
        {"function": 0, "index": 1, "name": "count"},
    ]
    assert data["other_spaces"] == {
        "global": [
            {"index": 0, "name": "heap_base"},
            {"index": 1, "name": "stack_ptr"},
        ]
    }
    kinds = {s["kind"] for s in data["subsections"]}
    assert {"module", "function", "local", "global"} <= kinds
    by_kind = {s["kind"]: s for s in data["subsections"]}
    assert by_kind["function"]["count"] == 3
    assert by_kind["global"]["count"] == 2
    assert "functions_truncated" not in data
    assert "spaces_truncated" not in data


def test_stripped_module_has_no_names(tmp_path: Path) -> None:
    """A module with no name section is empty, not an error."""
    data = _names(tmp_path, _module(_section(1, _uleb(0))))  # a type section, no names
    assert data["has_name_section"] is False
    assert data["module_name"] == ""
    assert data["functions"] == []
    assert data["function_count"] == 0
    assert data["locals"] == []
    assert data["other_spaces"] == {}
    assert data["subsections"] == []


def test_function_names_are_capped_with_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_NAME_ENTRIES", 2)
    section = _name_section(
        _subsection(1, _namemap([(0, "f0"), (1, "f1"), (2, "f2")]))
    )
    data = _names(tmp_path, _module(section))
    assert len(data["functions"]) == 2
    assert data["functions_truncated"] is True
    # The declared vec count stays the real total, so the cap is honest.
    assert data["functions_total"] == 3


def test_a_faulty_subsection_does_not_lose_the_names_before_it(tmp_path: Path) -> None:
    """A malformed subsection is recorded and skipped; earlier ones survive.

    The function names come first, then a local subsection whose interior name
    length runs past its own bytes. The parse must keep the functions, still flag
    the name section as present, and resync to the next subsection boundary.
    """
    good_functions = _subsection(1, _namemap([(0, "keep_me")]))
    # A local map claiming a 50-byte name with only 2 bytes left in the subsection.
    bad_local_payload = _uleb(1) + _uleb(0) + _uleb(1) + _uleb(0) + _uleb(50) + b"ab"
    bad_local = _subsection(2, bad_local_payload)
    data = _names(tmp_path, _module(_name_section(good_functions, bad_local)))

    assert data["has_name_section"] is True
    assert data["functions"] == [{"index": 0, "name": "keep_me"}]
    assert data["locals"] == []  # the faulty local map yielded nothing
    kinds = {s["kind"] for s in data["subsections"]}
    assert {"function", "local"} <= kinds  # both are still disclosed


def test_unknown_subsection_is_disclosed_not_materialised(tmp_path: Path) -> None:
    """An extended/indirect subsection we do not map is still listed, not dropped."""
    # id 3 == label names (an indirect namemap this reader discloses but does not
    # flatten); its bytes are opaque here, just enough to have a size.
    section = _name_section(
        _subsection(1, _namemap([(0, "f")])),
        _subsection(3, b"\x00"),
    )
    data = _names(tmp_path, _module(section))
    by_id = {s["id"]: s for s in data["subsections"]}
    assert by_id[3]["kind"] == "label"
    assert "label" not in data["other_spaces"]
    assert data["functions"] == [{"index": 0, "name": "f"}]


def test_needs_no_wabt(tmp_path: Path) -> None:
    client = WasmClient()
    client._wasm2wat = None
    client._objdump = None
    client._decompile = None
    assert client.available is False
    section = _name_section(_subsection(1, _namemap([(0, "only_fn")])))
    data = client.names(_write(tmp_path, _module(section)))
    assert data["functions"] == [{"index": 0, "name": "only_fn"}]


def test_bad_magic_is_a_clean_backend_error(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        _names(tmp_path, b"\x7fELF not a wasm module at all")
    assert excinfo.value.code == "backend_error"
    assert "WebAssembly" in excinfo.value.message


def test_section_overrun_is_a_clean_backend_error(tmp_path: Path) -> None:
    overrun = b"\x00" + _uleb(200) + b"\x00\x00"  # custom section overruns module
    with pytest.raises(JsReError) as excinfo:
        _names(tmp_path, _module(overrun))
    assert excinfo.value.code == "backend_error"
    assert "malformed" in excinfo.value.message


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().names(tmp_path / "nope.wasm")
    assert excinfo.value.code == "not_found"


def test_docstring_names_the_fields() -> None:
    doc = WasmClient.names.__doc__ or ""
    for token in ("function", "local", "name"):
        assert token in doc, token
