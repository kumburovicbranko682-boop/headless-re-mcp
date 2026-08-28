"""wasm.summary parses the section table in pure Python (no wabt required)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, WasmClient
from headless_re_mcp.backends.jsre.wasm_summary import summarize_wasm
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


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _uleb(len(raw)) + raw


def _vec(items: list[bytes]) -> bytes:
    return _uleb(len(items)) + b"".join(items)


def _section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _sample_module() -> bytes:
    """A small but structurally complete module touching every section kind."""
    functype = b"\x60" + _vec([b"\x7f", b"\x7f"]) + _vec([b"\x7f"])  # (i32,i32)->i32
    type_sec = _section(1, _vec([functype]))

    imp_func = _name("wasi_snapshot_preview1") + _name("fd_write") + b"\x00" + _uleb(0)
    imp_global = _name("env") + _name("STACK_MAX") + b"\x03" + b"\x7f" + b"\x00"
    import_sec = _section(2, _vec([imp_func, imp_global]))

    func_sec = _section(3, _vec([_uleb(0)]))  # one defined function, type 0

    mem = b"\x01" + _uleb(2) + _uleb(16)  # min 2, max 16 pages, not shared
    mem_sec = _section(5, _vec([mem]))

    glob = b"\x7f" + b"\x01" + b"\x41\x00\x0b"  # mutable i32, init i32.const 0
    global_sec = _section(6, _vec([glob]))

    exp_add = _name("add") + b"\x00" + _uleb(1)  # func index 1 (import func is 0)
    exp_mem = _name("memory") + b"\x02" + _uleb(0)  # memory index 0
    export_sec = _section(7, _vec([exp_add, exp_mem]))

    start_sec = _section(8, _uleb(1))

    data_seg = b"\x00" + b"\x41\x00\x0b" + _vec([b"h", b"i"])  # active, "hi"
    data_sec = _section(11, _vec([data_seg]))

    name_sub_payload = _name("mymod")
    name_sub = b"\x00" + _uleb(len(name_sub_payload)) + name_sub_payload
    custom_name = _section(0, _name("name") + name_sub)
    custom_producers = _section(0, _name("producers") + b"\x00")

    return (
        b"\x00asm"
        + b"\x01\x00\x00\x00"
        + type_sec
        + import_sec
        + func_sec
        + mem_sec
        + global_sec
        + export_sec
        + start_sec
        + data_sec
        + custom_name
        + custom_producers
    )


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


def test_summary_lays_out_the_section_table_and_counts() -> None:
    summary = summarize_wasm(_sample_module())

    assert summary["version"] == 1
    assert summary["truncated"] is False
    assert summary["malformed_sections"] == []

    assert summary["type_count"] == 1
    assert summary["function_count"] == 1
    assert summary["memory_count"] == 1
    assert summary["global_count"] == 1
    assert summary["data_segment_count"] == 1
    assert summary["start_function"] == 1

    names = {entry["name"] for entry in summary["sections"]}
    assert {"type", "import", "function", "memory", "global", "export", "start"} <= names
    # Every section reports its offset and (for the vector sections) a count.
    type_entry = next(e for e in summary["sections"] if e["name"] == "type")
    assert type_entry["count"] == 1
    assert type_entry["offset"] > 0


def test_summary_folds_the_import_surface() -> None:
    summary = summarize_wasm(_sample_module())

    assert summary["import_count"] == 2
    assert summary["import_kinds"] == {"func": 1, "table": 0, "memory": 0, "global": 1}
    assert summary["imports_truncated"] is False

    by_name = {item["name"]: item for item in summary["imports"]}
    assert by_name["fd_write"]["module"] == "wasi_snapshot_preview1"
    assert by_name["fd_write"]["kind"] == "func"
    assert by_name["fd_write"]["type_index"] == 0
    assert by_name["STACK_MAX"]["kind"] == "global"
    assert by_name["STACK_MAX"]["value_type"] == "i32"
    assert by_name["STACK_MAX"]["mutable"] is False


def test_summary_folds_the_export_surface_and_memory() -> None:
    summary = summarize_wasm(_sample_module())

    assert summary["export_count"] == 2
    assert summary["export_kinds"] == {"func": 1, "table": 0, "memory": 1, "global": 0}
    by_name = {item["name"]: item for item in summary["exports"]}
    assert by_name["add"] == {"name": "add", "kind": "func", "index": 1}
    assert by_name["memory"] == {"name": "memory", "kind": "memory", "index": 0}

    assert summary["memories"] == [
        {"initial_pages": 2, "max_pages": 16, "shared": False}
    ]


def test_summary_reads_the_name_section_and_custom_list() -> None:
    summary = summarize_wasm(_sample_module())

    assert summary["has_name_section"] is True
    assert summary["module_name"] == "mymod"
    assert summary["custom_sections"] == ["name", "producers"]


def test_summary_flags_a_module_truncated_mid_section() -> None:
    """A binary that ends inside a declared section reports truncated, not raises."""
    module = _sample_module()
    summary = summarize_wasm(module[: len(module) - 5])
    assert summary["truncated"] is True
    # What parsed before the cut is still reported.
    assert summary["version"] == 1
    assert summary["type_count"] == 1


def test_summary_rejects_a_bad_magic_without_raising() -> None:
    summary = summarize_wasm(b"MZ\x90\x00 not wasm at all")
    assert "magic" in summary["malformed_sections"]
    assert summary["version"] is None


def test_summary_survives_a_declared_size_past_eof() -> None:
    """A section claiming more bytes than remain is recorded, then the walk stops."""
    # magic + version, then a type section id (1) claiming 200 bytes but with none.
    module = b"\x00asm\x01\x00\x00\x00" + bytes([1]) + _uleb(200)
    summary = summarize_wasm(module)
    assert summary["truncated"] is True
    assert summary["section_count"] == 1
    assert summary["sections"][0]["name"] == "type"


def test_summary_isolates_a_malformed_section(tmp_path: Path) -> None:
    """A section whose body is garbage is listed in malformed_sections, not fatal."""
    # An import section whose declared vector count cannot be satisfied.
    bad_import = _section(2, b"\x05")  # says 5 imports, provides none
    trailing_type = _section(1, _vec([b"\x60" + _vec([]) + _vec([])]))
    module = b"\x00asm\x01\x00\x00\x00" + bad_import + trailing_type
    summary = summarize_wasm(module)
    assert "import" in summary["malformed_sections"]
    # The walk continued to the well-formed section after it.
    assert summary["type_count"] == 1


def test_wasm_client_summary_needs_no_wabt(tmp_path: Path) -> None:
    """summary must work with wabt unconfigured (unlike wat/info)."""
    module = tmp_path / "m.wasm"
    module.write_bytes(_sample_module())
    client = WasmClient(None)
    assert client.available is False  # wat/info would be capability_unavailable
    payload = client.summary(module)
    assert payload["version"] == 1
    assert payload["import_count"] == 2


def test_wasm_client_summary_rejects_non_wasm(tmp_path: Path) -> None:
    bad = tmp_path / "n.wasm"
    bad.write_bytes(b"\x7fELF definitely not wasm")
    with pytest.raises(JsReError) as caught:
        WasmClient(None).summary(bad)
    assert caught.value.code == "invalid_params"


def test_wasm_client_summary_refuses_oversized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.jsre import client as mod

    monkeypatch.setattr(mod, "_MAX_INPUT_BYTES", 16)
    module = tmp_path / "m.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00" + b"\x00" * 64)
    with pytest.raises(JsReError) as caught:
        WasmClient(None).summary(module)
    assert caught.value.code == "too_large"


def test_wasm_summary_docstring_names_the_shape() -> None:
    doc = _tool_docstring("wasm.summary")
    assert "imports" in doc
    assert "exports" in doc
    assert "sections" in doc
    assert "start_function" in doc
    assert "too_large" in doc
    assert "invalid_params" in doc


def test_summary_service_reports_the_pure_python_backend(tmp_path: Path) -> None:
    """The service tags summary with a non-wabt backend so callers can tell."""
    from headless_re_mcp.core.service import AnalysisService

    module = tmp_path / "m.wasm"
    module.write_bytes(_sample_module())
    service = AnalysisService()
    try:
        result = service.wasm_summary(str(module))
    finally:
        service.close_all()
    payload = result.model_dump(mode="json")
    assert payload["ok"] is True
    assert payload["meta"]["backend"] == "wasm-parser"
    assert payload["data"]["module_name"] == "mymod"
