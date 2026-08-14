"""breakpoints.hardware.remove must name the removed flag it returns."""

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


def _remove_hw_return() -> str:
    source = Path(r"native/xdbg-headless-rpc/rpc_methods.cpp").read_text(encoding="utf-8")
    start = source.index("Outcome RemoveHardwareBreakpointRpc(")
    chunk = source[start : source.index("Outcome ListHardwareBreakpoints", start)]
    return chunk[chunk.rindex("auto result = JsonObject()") :]


def test_hardware_remove_answers_with_removed_not_set() -> None:
    """The catalog said remove and never named the flag.

    Measured: RemoveHardwareBreakpointRpc JsonSets address and removed.
    There is no set field. Software remove echoes set false; looking
    for that after a hardware delete treats a live clear as still armed.
    """
    returned = _remove_hw_return()
    assert 'JsonSet(result.get(), "address"' in returned
    assert 'JsonSet(result.get(), "removed"' in returned
    assert 'JsonSet(result.get(), "set"' not in returned
    described = _tool_docstring("breakpoints.hardware.remove")
    assert "Answers with address and removed" in described
    assert "no set field" in described
