"""threads.context.write must name the name/value/tid fields it returns."""

from __future__ import annotations

import ast
from pathlib import Path

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


def _write_thread_context() -> str:
    source = Path(r"native/xdbg-headless-rpc/rpc_methods.cpp").read_text(encoding="utf-8")
    start = source.index("Outcome WriteThreadContext(")
    return source[start : source.index("Outcome ReadStack(", start)]


def test_threads_context_write_answers_with_name_value_and_tid() -> None:
    """The catalog said write and never named the echo.

    Measured: WriteThreadContext returns WriteRegister name/value plus tid
    and restored_tid. There is no written, ok, registers or context.
    Looking for written after success treats a live poke as a no-op.
    """
    chunk = _write_thread_context()
    assert "WriteRegister(params)" in chunk
    assert 'JsonSet(written.value.get(), "tid"' in chunk
    assert 'JsonSet(written.value.get(), "restored_tid"' in chunk
    assert 'JsonSet(written.value.get(), "written"' not in chunk
    assert 'JsonSet(written.value.get(), "ok"' not in chunk
    described = _tool_docstring("threads.context.write")
    assert "Answers with name and value" in described
    assert "tid" in described
    assert "restored_tid" in described
    assert "no written" in described
