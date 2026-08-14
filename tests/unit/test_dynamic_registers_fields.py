"""dynamic.registers.read must name the nested registers object it returns."""

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


def _read_registers_return() -> str:
    source = Path(r"native/xdbg-headless-rpc/rpc_methods.cpp").read_text(encoding="utf-8")
    start = source.index("Outcome ReadRegisters()")
    chunk = source[start : source.index("bool IsWritableRegister", start)]
    return chunk[chunk.rindex("auto result = JsonObject()") :]


def test_dynamic_registers_read_puts_gprs_under_registers_not_rip() -> None:
    """The catalog said register set and never named the object.

    Measured: ReadRegisters JsonSets a nested registers object (rax..r15,
    rip, eflags, dr0-dr7 on x64). FakeDynamicWorker and
    tests/unit/test_dynamic_service.py already read data['registers']['rip'].
    There is no top-level rip, gpr or context. Looking for rip after a
    successful read treats a live paused debuggee as empty, so the overnight
    pass retries or arms breakpoints from a stale VA.
    """
    returned = _read_registers_return()
    assert 'JsonSet(result.get(), "registers"' in returned
    assert 'JsonSet(result.get(), "rip"' not in returned
    assert 'JsonSet(result.get(), "gpr"' not in returned
    assert 'JsonSet(result.get(), "context"' not in returned
    fake = Path("tests/unit/test_dynamic_service.py").read_text(encoding="utf-8")
    assert 'return {"registers": {"rip": 0x140001000, "rsp": 0x120000}}' in fake
    described = _tool_docstring("dynamic.registers.read")
    assert "Answers with registers" in described
    assert "no top-level rip" in described
    assert "gpr" in described
    assert "context" in described

def test_dynamic_registers_write_schema_matches_native_register_name_cap() -> None:
    """The catalog accepted an unbounded register name.

    Measured: input schema name has no maximum. Native WriteRegister reads
    name with a 16-byte cap. A caller that sends a huge name still occupies a
    worker until the adapter refuses, and the catalog never said the write
    would be rejected.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome WriteRegister")
    chunk = native[start : native.index("char HexDigit", start)]
    assert 'ReadString(params, "name", name, error, true, 16)' in chunk
    handler = next(
        binding.handler
        for binding in build_dynamic_tools(object())  # type: ignore[arg-type]
        if binding.name == "dynamic.registers.write"
    )
    props = input_schema_for(handler)["properties"]
    assert props["name"]["minLength"] == 1
    assert props["name"]["maxLength"] == 16
