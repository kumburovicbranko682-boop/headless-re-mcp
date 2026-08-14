"""memory.protect.query description must name protect_name."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_dynamic_analysis_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_memory_protect_query_puts_the_result_in_protect_name(tmp_path: Path) -> None:
    """The catalog said query the region and never named the payload.

    Measured via the paused fake worker: protect_name=execute_read, protect=32,
    plus base/size/state/type; no protection, region or rights field. Looking
    for those after a successful query reads as VirtualQuery finding none.
    """
    from tests.unit.test_dynamic_service import (
        FakeDynamicWorker,
        _create,
        _service,
        _state,
        _write_minimal_pe,
    )

    binary = tmp_path / "f.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    result = service.memory_protect_query(session_id, worker.module_base + 0x10)
    assert result.ok and result.data is not None
    payload: dict[str, Any] = result.data
    assert payload["protect_name"] == "execute_read"
    assert payload["protect"] == 32
    assert "protection" not in payload
    assert "region" not in payload
    assert "rights" not in payload
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("JsonPtr MemoryRegionObject")
    chunk = native[start : native.index("Outcome ListMemoryRegions", start)]
    assert 'JsonSet(value.get(), "protect_name"' in chunk
    assert 'JsonSet(value.get(), "protect"' in chunk
    doc = _tool_docstring("memory.protect.query")
    assert "Answers with protect_name" in doc
    assert "protect" in doc
    assert "no protection" in doc
