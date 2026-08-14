"""breakpoints.memory.set description must name set, not ok."""

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


def test_memory_bp_set_puts_success_in_set_not_ok() -> None:
    """The catalog said set a memory breakpoint and never named the payload.

    Measured against SetMemoryBreakpointRpc: success is set true, plus
    address and type. There is no ok or memory field. Looking for ok after
    a successful set reads as the page BP not armed, so the agent retries
    SetMemoryBPX on the same VA.
    """
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome SetMemoryBreakpointRpc")
    chunk = native[start : native.index("Outcome RemoveMemoryBreakpointRpc", start)]
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert 'JsonSet(result.get(), "set"' in returned
    assert 'JsonSet(result.get(), "address"' in returned
    assert 'JsonSet(result.get(), "type"' in returned
    assert '"ok"' not in returned
    assert '"memory"' not in returned
    doc = _tool_docstring("breakpoints.memory.set")
    assert "Answers with set" in doc
    assert "no ok" in doc
