"""Tests for WasmClient.memory, the module linear-memory map reader.

Like the summary/globals/data tests these build tiny modules by hand so the
parser runs with no wabt: wasm.memory walks the module binary's import, memory,
data-count and data sections directly. It lists the declared linear memories
(imported and defined) with their page limits and byte sizes, then folds the
Data section into a placement map -- each segment's mode, target memory,
resolved offset, size and end -- plus an ``occupied`` span, the linear-memory
range the static image covers. Those sizes are what frame every wasm.data /
wasm.strings / wasm.globals offset.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsReError,
    WasmClient,
    _parse_wasm_memory,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

PAGE = 65536


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


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _module(*sections: bytes) -> bytes:
    return b"\x00asm" + (1).to_bytes(4, "little") + b"".join(sections)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _memtype(
    minimum: int,
    maximum: int | None = None,
    *,
    shared: bool = False,
    is64: bool = False,
) -> bytes:
    flags = 0
    if maximum is not None:
        flags |= 0x01
    if shared:
        flags |= 0x02
    if is64:
        flags |= 0x04
    out = bytes([flags]) + _uleb(minimum)
    if maximum is not None:
        out += _uleb(maximum)
    return out


def _memory_section(*mems: bytes) -> bytes:
    return _section(5, _uleb(len(mems)) + b"".join(mems))


def _import_memory(
    module: str,
    field: str,
    minimum: int,
    maximum: int | None = None,
    *,
    shared: bool = False,
    is64: bool = False,
) -> bytes:
    return (
        _name(module)
        + _name(field)
        + b"\x02"
        + _memtype(minimum, maximum, shared=shared, is64=is64)
    )


def _import_func(module: str, field: str, type_index: int) -> bytes:
    return _name(module) + _name(field) + b"\x00" + _uleb(type_index)


def _import_section(*imports: bytes) -> bytes:
    return _section(2, _uleb(len(imports)) + b"".join(imports))


def _data_active(offset: int, blob: bytes) -> bytes:
    return b"\x00" + b"\x41" + _sleb(offset) + b"\x0b" + _uleb(len(blob)) + blob


def _data_active_mem(memidx: int, offset: int, blob: bytes) -> bytes:
    return (
        b"\x02"
        + _uleb(memidx)
        + b"\x41"
        + _sleb(offset)
        + b"\x0b"
        + _uleb(len(blob))
        + blob
    )


def _data_active_globalbase(gidx: int, blob: bytes) -> bytes:
    return b"\x00" + b"\x23" + _uleb(gidx) + b"\x0b" + _uleb(len(blob)) + blob


def _data_passive(blob: bytes) -> bytes:
    return b"\x01" + _uleb(len(blob)) + blob


def _data_section(*segs: bytes) -> bytes:
    return _section(11, _uleb(len(segs)) + b"".join(segs))


def _datacount_section(n: int) -> bytes:
    return _section(12, _uleb(n))


def _export_memory(name: str, index: int) -> bytes:
    return _name(name) + b"\x02" + _uleb(index)


def _export_section(*exports: bytes) -> bytes:
    return _section(7, _uleb(len(exports)) + b"".join(exports))


def _memory_name_section(*pairs: tuple[int, str]) -> bytes:
    namemap = _uleb(len(pairs)) + b"".join(_uleb(i) + _name(nm) for i, nm in pairs)
    sub = bytes([6]) + _uleb(len(namemap)) + namemap
    return _section(0, _name("name") + sub)


def _write(tmp_path: Path, data: bytes, name: str = "m.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


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


def test_defined_memory_carries_pages_and_bytes() -> None:
    """The headline case: a defined memory with a minimum and no maximum."""
    out = _parse_wasm_memory(_module(_memory_section(_memtype(2))), module="m.wasm")
    assert out["memory_count"] == 1
    assert out["imported_count"] == 0
    assert out["defined_count"] == 1
    assert out["page_size"] == PAGE
    (mem,) = out["memories"]
    assert mem["index"] == 0
    assert mem["kind"] == "defined"
    assert mem["min_pages"] == 2
    assert mem["max_pages"] is None
    assert mem["min_bytes"] == 2 * PAGE
    assert mem["max_bytes"] is None
    assert mem["shared"] is False
    assert mem["index_type"] == "i32"


def test_defined_memory_with_maximum_scales_bytes() -> None:
    out = _parse_wasm_memory(
        _module(_memory_section(_memtype(1, 10))), module="m.wasm"
    )
    (mem,) = out["memories"]
    assert mem["max_pages"] == 10
    assert mem["max_bytes"] == 10 * PAGE


def test_shared_memory_flag_is_reported() -> None:
    out = _parse_wasm_memory(
        _module(_memory_section(_memtype(1, 2, shared=True))), module="m.wasm"
    )
    (mem,) = out["memories"]
    assert mem["shared"] is True
    assert mem["max_pages"] == 2


def test_memory64_index_type_is_reported() -> None:
    out = _parse_wasm_memory(
        _module(_memory_section(_memtype(1, is64=True))), module="m.wasm"
    )
    (mem,) = out["memories"]
    assert mem["index_type"] == "i64"


def test_imported_memory_takes_low_index_and_carries_origin() -> None:
    out = _parse_wasm_memory(
        _module(
            _import_section(_import_memory("env", "memory", 1, 4)),
            _memory_section(_memtype(2)),
        ),
        module="m.wasm",
    )
    assert out["imported_count"] == 1
    assert out["defined_count"] == 1
    assert out["memory_count"] == 2
    imported, defined = out["memories"]
    assert imported["index"] == 0
    assert imported["kind"] == "imported"
    assert imported["module"] == "env"
    assert imported["import_name"] == "memory"
    assert imported["min_pages"] == 1
    assert imported["max_pages"] == 4
    assert defined["index"] == 1
    assert defined["kind"] == "defined"


def test_func_import_does_not_consume_a_memory_index() -> None:
    out = _parse_wasm_memory(
        _module(
            _import_section(
                _import_func("env", "log", 0),
                _import_memory("env", "memory", 1),
            ),
        ),
        module="m.wasm",
    )
    (imported,) = out["memories"]
    assert imported["index"] == 0  # the func import did not take index 0
    assert imported["import_name"] == "memory"


def test_active_data_segment_resolves_offset_and_end() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(_data_active(1024, b"\x01\x02\x03\x04")),
        ),
        module="m.wasm",
    )
    assert out["segment_count"] == 1
    assert out["active_segments"] == 1
    assert out["passive_segments"] == 0
    (seg,) = out["segments"]
    assert seg["index"] == 0
    assert seg["mode"] == "active"
    assert seg["memory_index"] == 0
    assert seg["offset"] == 1024
    assert seg["size"] == 4
    assert seg["end"] == 1028
    assert out["occupied"] == {"start": 1024, "end": 1028, "size": 4}


def test_passive_segment_has_no_placement() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(_data_passive(b"abcd")),
        ),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "passive"
    assert seg["memory_index"] is None
    assert seg["offset"] is None
    assert seg["end"] is None
    assert seg["size"] == 4
    assert out["passive_segments"] == 1
    assert out["active_segments"] == 0
    assert out["occupied"] is None  # nothing is placed in linear memory


def test_explicit_memory_index_segment_is_reported() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(_data_active_mem(0, 16, b"xy")),
        ),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "active"
    assert seg["memory_index"] == 0
    assert seg["offset"] == 16
    assert seg["end"] == 18


def test_global_base_segment_offset_is_null_but_stays_active() -> None:
    """An active segment whose base is an imported global.get has no resolved offset."""
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(_data_active_globalbase(0, b"zzzz")),
        ),
        module="m.wasm",
    )
    (seg,) = out["segments"]
    assert seg["mode"] == "active"
    assert seg["offset"] is None
    assert seg["end"] is None
    assert out["active_segments"] == 1
    assert out["occupied"] is None  # unresolved base cannot join the span


def test_occupied_unions_multiple_active_segments() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(
                _data_active(100, b"a" * 10),
                _data_passive(b"skip"),
                _data_active(500, b"b" * 20),
            ),
        ),
        module="m.wasm",
    )
    assert out["segment_count"] == 3
    assert out["active_segments"] == 2
    assert out["passive_segments"] == 1
    assert out["occupied"] == {"start": 100, "end": 520, "size": 420}


def test_data_count_section_is_surfaced() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _datacount_section(2),
            _data_section(_data_active(0, b"a"), _data_passive(b"b")),
        ),
        module="m.wasm",
    )
    assert out["data_count"] == 2


def test_missing_data_count_is_null() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(_data_active(0, b"a")),
        ),
        module="m.wasm",
    )
    assert out["data_count"] is None


def test_no_memory_section_is_a_clean_empty_map() -> None:
    out = _parse_wasm_memory(_module(), module="m.wasm")
    assert out["memories"] == []
    assert out["memory_count"] == 0
    assert out["segments"] == []
    assert out["segment_count"] == 0
    assert out["occupied"] is None
    assert out["data_count"] is None
    assert out["has_name_section"] is False


def test_export_name_attaches_to_the_memory() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _export_section(_export_memory("memory", 0)),
        ),
        module="m.wasm",
    )
    (mem,) = out["memories"]
    assert mem["exported_as"] == ["memory"]


def test_name_section_memory_namemap_attaches_name() -> None:
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _memory_name_section((0, "main_mem")),
        ),
        module="m.wasm",
    )
    (mem,) = out["memories"]
    assert mem["name"] == "main_mem"
    assert out["has_name_section"] is True


def test_has_name_section_false_without_namemap() -> None:
    out = _parse_wasm_memory(_module(_memory_section(_memtype(1))), module="m.wasm")
    assert out["has_name_section"] is False
    assert "name" not in out["memories"][0]


def test_segments_truncated_when_over_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_MEM_SEGMENTS", 2)
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _data_section(
                _data_active(0, b"a"),
                _data_active(100, b"b"),
                _data_active(200, b"c"),
            ),
        ),
        module="m.wasm",
    )
    assert out["segments_truncated"] is True
    assert len(out["segments"]) == 2
    # tallies and the occupied span still reflect every segment
    assert out["segment_count"] == 3
    assert out["active_segments"] == 3
    assert out["occupied"] == {"start": 0, "end": 201, "size": 201}


def test_memories_truncated_when_over_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_WASM_MEMORIES", 1)
    out = _parse_wasm_memory(
        _module(_memory_section(_memtype(1), _memtype(2))), module="m.wasm"
    )
    assert out["memories_truncated"] is True
    assert len(out["memories"]) == 1
    # the count still discloses the true total
    assert out["memory_count"] == 2
    assert out["defined_count"] == 2


def test_malformed_memory_section_is_backend_error() -> None:
    """A memory count with no memtype bytes runs off the end into backend_error."""
    with pytest.raises(JsReError) as excinfo:
        _parse_wasm_memory(_module(_section(5, _uleb(1))), module="m.wasm")
    assert excinfo.value.code == "backend_error"


def test_bad_magic_is_a_clean_backend_error() -> None:
    with pytest.raises(JsReError) as excinfo:
        _parse_wasm_memory(b"not a wasm module", module="junk.bin")
    assert excinfo.value.code == "backend_error"


def test_malformed_data_vec_desyncs_and_discloses() -> None:
    """A data segment claiming more bytes than remain stops the vec, keeps the rest."""
    good = _data_active(0, b"ok")
    bad = b"\x00" + b"\x41" + _sleb(0) + b"\x0b" + _uleb(99)  # 99 bytes, none supplied
    out = _parse_wasm_memory(
        _module(
            _memory_section(_memtype(1)),
            _section(11, _uleb(2) + good + bad),
        ),
        module="m.wasm",
    )
    assert out["parse_stopped"] is True
    assert out["active_segments"] == 1
    assert out["segments"][0]["offset"] == 0


def test_missing_file_is_not_found() -> None:
    with pytest.raises(JsReError) as excinfo:
        WasmClient().memory(Path("/no/such/module.wasm"))
    assert excinfo.value.code == "not_found"


def test_service_wires_through(tmp_path: Path) -> None:
    """The service method returns the map under the wabt backend tag."""
    service = AnalysisService(Settings.load())
    path = _write(
        tmp_path,
        _module(
            _import_section(_import_memory("env", "memory", 1, 4)),
            _memory_section(_memtype(2)),
            _data_section(_data_active(1024, b"\x01\x02\x03\x04")),
            _memory_name_section((1, "heap")),
        ),
    )
    result = service.wasm_memory(str(path))
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "wabt"
    assert result.data["memory_count"] == 2
    assert result.data["occupied"] == {"start": 1024, "end": 1028, "size": 4}
    names = {m["index"]: m.get("name") for m in result.data["memories"]}
    assert names[1] == "heap"


def test_service_reports_a_bad_module_cleanly(tmp_path: Path) -> None:
    service = AnalysisService(Settings.load())
    path = _write(tmp_path, b"\x00asm\x01\x00\x00", name="bad.wasm")
    result = service.wasm_memory(str(path))
    assert not result.ok
    assert result.error is not None


def test_docstring_frames_it_as_the_memory_map() -> None:
    doc = _tool_docstring("wasm.memory")
    for token in ("memories", "segments", "occupied", "page_size", "data_count"):
        assert token in doc, token
