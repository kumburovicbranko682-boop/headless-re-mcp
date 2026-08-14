"""memory.regions must name the field the x64dbg adapter actually returns."""

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


def _list_memory_regions_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ListMemoryRegions")
    return native[start : native.index("Outcome QueryMemoryProtect", start)]


def test_memory_regions_description_names_regions_not_items() -> None:
    """The catalog said pagination and never named the list field.

    Measured against ListMemoryRegions: the page is regions, with count, total,
    offset, limit and has_more. There is no items or memory field.
    tests/unit/test_dynamic_service.py already drives a fake worker that puts
    the page in regions. Looking for items after a successful list reads as
    VirtualQuery finding none.
    """
    chunk = _list_memory_regions_cpp()
    assert 'JsonSet(result.get(), "regions"' in chunk
    assert 'JsonSet(result.get(), "count"' in chunk
    assert 'JsonSet(result.get(), "total"' in chunk
    assert 'JsonSet(result.get(), "has_more"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"items"' not in returned
    assert '"memory"' not in returned
    described = _tool_docstring("memory.regions")
    assert "Answers with regions" in described
    assert "has_more" in described
    assert "no items" in described
    assert "no memory field" in described

def _trace_stack_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome TraceStack")
    return native[start : native.index("Outcome ReadDisassembly", start)]


def test_stack_trace_description_names_frames_not_stack() -> None:
    """The catalog said call stack and never named the list field.

    Measured against TraceStack: the page is frames, with count, total, limit
    and has_more. There is no stack or items field. Looking for stack after a
    successful trace reads as an empty call stack.
    """
    chunk = _trace_stack_cpp()
    assert 'JsonSet(result.get(), "frames"' in chunk
    assert 'JsonSet(result.get(), "count"' in chunk
    assert 'JsonSet(result.get(), "total"' in chunk
    assert 'JsonSet(result.get(), "has_more"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"stack"' not in returned
    assert '"items"' not in returned
    described = _tool_docstring("stack.trace")
    assert "Answers with frames" in described
    assert "has_more" in described
    assert "no stack field" in described
    assert "no items" in described

def _read_disassembly_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ReadDisassembly")
    return native[start : native.index("struct BoundedSymbolContext", start)]


def test_disassembly_read_description_names_instructions_not_disasm() -> None:
    """The catalog said disassemble and never named the list field.

    Measured against ReadDisassembly: the page is instructions, each carrying
    instruction (not text), plus address and count. There is no disasm or items
    field. Looking for disasm after a successful read reads as empty.
    """
    chunk = _read_disassembly_cpp()
    assert 'JsonSet(result.get(), "instructions"' in chunk
    assert 'JsonSet(value.get(), "instruction"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"disasm"' not in returned
    assert '"items"' not in returned
    assert '"text"' not in returned
    described = _tool_docstring("disassembly.read")
    assert "Answers with instructions" in described
    assert "instruction" in described
    assert "no disasm field" in described
    assert "no items" in described
    assert "no text field" in described

def _current_thread_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("JsonPtr ThreadObject")
    return native[start : native.index("bool SwitchThread", start)]


def test_threads_current_description_names_tid_not_thread() -> None:
    """The catalog said current thread and never named the payload fields.

    Measured against CurrentThread: success is a ThreadObject at the top level
    (tid, entry, teb, cip, name, suspend_count, current). There is no thread
    field. Looking for thread after a successful read reads as no current TID.
    """
    chunk = _current_thread_cpp()
    assert 'JsonSet(value.get(), "tid"' in chunk
    assert 'JsonSet(value.get(), "entry"' in chunk
    assert 'JsonSet(value.get(), "cip"' in chunk
    assert "ThreadObject(list.list[list.CurrentThread], true)" in chunk
    success = chunk[chunk.index("Outcome CurrentThread") :]
    assert '"thread"' not in success
    described = _tool_docstring("threads.current")
    assert "Answers with tid" in described
    assert "no thread field" in described
