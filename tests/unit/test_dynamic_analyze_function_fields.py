"""dynamic.analyze_function must name the nested report it returns."""

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


def test_analyze_function_puts_the_stop_under_execution_not_rip() -> None:
    """The catalog named stopped_at_breakpoint and not the rest of the report.

    Measured: analyze_function_dynamic returns function, static, breakpoint,
    execution and registers. tests/unit/test_dynamic_service.py already reads
    function.static_address, breakpoint.armed and
    execution.stopped_at_breakpoint. There is no top-level rip or decompiled.
    Looking for rip after success treats a live stop as empty.
    """
    service = Path("src/headless_re_mcp/core/service.py").read_text(encoding="utf-8")
    start = service.index("def analyze_function_dynamic(")
    chunk = service[start : service.index("def _explicit_module_operation(", start)]
    assert '"function":' in chunk
    assert '"static": static_section' in chunk
    assert '"breakpoint":' in chunk
    assert '"execution": execution' in chunk
    assert '"registers": registers' in chunk
    assert "if not resumed.ok" in chunk
    assert '"rip"' not in chunk
    described = _tool_docstring("dynamic.analyze_function")
    assert "Answers with function" in described
    assert "execution" in described
    assert "registers" in described
    assert "no top-level rip" in described
