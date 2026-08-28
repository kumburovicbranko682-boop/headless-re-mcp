"""breakpoints.hardware.set description must name set, not ok."""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

from headless_re_mcp.tools.binding import input_schema_for
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


def test_hardware_set_puts_success_in_set_not_ok() -> None:
    """The catalog said set a hardware breakpoint and never named the payload.

    Measured against SetHardwareBreakpointRpc: success is set true, plus
    address, type and size. There is no ok or hardware field. Looking for
    ok after a successful set reads as the DR slot not armed, so the agent
    retries SetHardwareBreakpoint until the debug registers are exhausted.
    """
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome SetHardwareBreakpointRpc")
    chunk = native[start : native.index("Outcome RemoveHardwareBreakpointRpc", start)]
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert 'JsonSet(result.get(), "set"' in returned
    assert 'JsonSet(result.get(), "address"' in returned
    assert 'JsonSet(result.get(), "type"' in returned
    assert 'JsonSet(result.get(), "size"' in returned
    assert '"ok"' not in returned
    assert '"hardware"' not in returned
    doc = _tool_docstring("breakpoints.hardware.set")
    assert "Answers with set" in doc
    assert "no ok" in doc


def test_hardware_set_size_is_an_enum_of_1_2_4_8() -> None:
    """size must be the x86 DR7 lengths only, not any 1..8 integer.

    x86 debug registers encode the watch length as 1/2/4/8 (Intel SDM), and the
    native ParseHardwareSize rejects everything else. The old Field(ge=1, le=8)
    bound also accepted 3/5/6/7, which then round-tripped to a paused debuggee
    only to be refused there, and contradicted the tool's "size enums only"
    docstring. The generated schema must expose exactly {1, 2, 4, 8}.
    """
    tools = build_dynamic_analysis_tools(MagicMock())
    handler = next(t.handler for t in tools if t.name == "breakpoints.hardware.set")

    schema = input_schema_for(handler)
    size = schema["properties"]["size"]

    assert size.get("enum") == [1, 2, 4, 8]
    assert size.get("default") == 1
    # A range bound would have advertised min/max instead of an enum.
    assert "maximum" not in size and "minimum" not in size
