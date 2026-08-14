"""dynamic.breakpoint.remove must name the address/set fields it returns."""

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


def _change_breakpoint_return() -> str:
    source = Path(r"native/xdbg-headless-rpc/rpc_methods.cpp").read_text(encoding="utf-8")
    start = source.index("Outcome ChangeBreakpoint(")
    chunk = source[start : source.index("bool ReadOptionalUnsigned", start)]
    return chunk[chunk.rindex("auto result = JsonObject()") :]


def test_dynamic_breakpoint_remove_answers_with_set_false_not_removed() -> None:
    """The catalog said remove and never named the echo fields.

    Measured: ChangeBreakpoint JsonSets address and set. FakeDynamicWorker
    returns set False on remove. There is no removed, ok or cleared field.
    Looking for removed after success treats a live DeleteBPX as still
    armed, so the overnight pass keeps hitting a breakpoint it thought
    it cleared.
    """
    returned = _change_breakpoint_return()
    assert 'JsonSet(result.get(), "address"' in returned
    assert 'JsonSet(result.get(), "set"' in returned
    assert 'JsonSet(result.get(), "removed"' not in returned
    assert 'JsonSet(result.get(), "ok"' not in returned
    assert 'JsonSet(result.get(), "cleared"' not in returned
    fake = Path("tests/unit/test_dynamic_service.py").read_text(encoding="utf-8")
    assert 'return {"address": address, "set": False}' in fake
    described = _tool_docstring("dynamic.breakpoint.remove")
    assert "Answers with address and set" in described
    assert "false" in described.lower()
    assert "no removed" in described
