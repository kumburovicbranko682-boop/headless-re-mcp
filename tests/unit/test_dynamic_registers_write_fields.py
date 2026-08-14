"""dynamic.registers.write must name the name/value fields it returns."""

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


def _write_register_return() -> str:
    source = Path(r"native/xdbg-headless-rpc/rpc_methods.cpp").read_text(encoding="utf-8")
    start = source.index("Outcome WriteRegister(")
    chunk = source[start : source.index("char HexDigit", start)]
    return chunk[chunk.rindex("auto result = JsonObject()") :]


def test_dynamic_registers_write_answers_with_name_and_value() -> None:
    """The catalog said write and never named the echo fields.

    Measured: WriteRegister JsonSets name and value. FakeDynamicWorker
    returns the same two keys. There is no written, ok or registers
    field. Looking for written after success treats a live register
    poke as a no-op, so the overnight pass retries or skips the next
    memory write that depended on it.
    """
    returned = _write_register_return()
    assert 'JsonSet(result.get(), "name"' in returned
    assert 'JsonSet(result.get(), "value"' in returned
    assert 'JsonSet(result.get(), "written"' not in returned
    assert 'JsonSet(result.get(), "ok"' not in returned
    assert 'JsonSet(result.get(), "registers"' not in returned
    fake = Path("tests/unit/test_dynamic_service.py").read_text(encoding="utf-8")
    assert 'return {"name": values["name"], "value": values["value"]}' in fake
    described = _tool_docstring("dynamic.registers.write")
    assert "Answers with name and value" in described
    assert "no written" in described
    assert "ok" in described
    assert "registers field" in described
