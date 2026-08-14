"""dynamic.memory.write must name the address/size fields it returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.dynamic import build_dynamic_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_dynamic_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def _write_memory_return() -> str:
    source = Path(r"native/xdbg-headless-rpc/rpc_methods.cpp").read_text(encoding="utf-8")
    start = source.index("Outcome WriteMemory(")
    chunk = source[start : source.index("const char* MemoryStateName", start)]
    return chunk[chunk.rindex("auto result = JsonObject()") :]


def test_dynamic_memory_write_answers_with_address_and_size() -> None:
    """The catalog said write and never named the echo fields.

    Measured: WriteMemory JsonSets address and size. FakeDynamicWorker
    returns the same two keys. There is no written, ok, data or bytes
    field. Looking for written after success treats a live patch as a
    no-op, so the overnight pass retries the write or dumps the stub.
    """
    returned = _write_memory_return()
    assert 'JsonSet(result.get(), "address"' in returned
    assert 'JsonSet(result.get(), "size"' in returned
    assert 'JsonSet(result.get(), "written"' not in returned
    assert 'JsonSet(result.get(), "ok"' not in returned
    assert 'JsonSet(result.get(), "data"' not in returned
    assert 'JsonSet(result.get(), "bytes"' not in returned
    fake = Path("tests/unit/test_dynamic_service.py").read_text(encoding="utf-8")
    assert '"address": values["address"]' in fake
    assert '"size": len(str(values["data"])) // 2' in fake
    described = _tool_docstring("dynamic.memory.write")
    assert "Answers with address and size" in described
    assert "no written" in described
    assert "ok" in described
    assert "data" in described
    assert "bytes" in described
