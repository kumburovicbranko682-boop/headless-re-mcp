"""static.functions must name the field the IDA worker actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.core import build_static_core_tools


def _docstring(name: str) -> str:
    source = Path(build_static_core_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_docstring(node) or ""
    return ""


def test_static_functions_description_names_items_not_functions() -> None:
    """The live catalog omitted the list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    functions.data['items'][0]['name']. The worker returns items with address,
    name, end, size and flags, and no functions field. A caller looking for
    functions after a successful list reads it as IDA finding none.
    """
    described = _docstring("static_functions")
    assert "Answers with items" in described
    assert "no functions field" in described
    assert "address" in described
    assert "end" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _functions")
    chunk = worker[start : start + 900]
    assert '"items": items' in chunk
    assert '"functions"' not in chunk.split("return")[-1]

def test_static_decompile_description_names_code_not_text() -> None:
    """The live catalog omitted the decompiled-text field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    decompiled.data['code']. The worker returns address, end and code, and no
    text field. A caller looking for text after a successful decompile reads
    it as IDA returning nothing.
    """
    described = _docstring("static_decompile")
    assert "Answers with code" in described
    assert "no text field" in described
    assert "address" in described
    assert "end" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _decompile")
    chunk = worker[start : worker.index("def _require_function", start)]
    assert '"code": text' in chunk
    returned = chunk.split("return")[-1]
    assert '"code"' in returned
    assert '"text"' not in returned

def test_static_strings_description_names_items_and_value() -> None:
    """The live catalog omitted the list field and named the string body wrong.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    strings.data['items'][0]['value']. The worker returns items with address,
    length, type, value and truncated, and no strings or text field. A caller
    looking for strings or text after a successful list reads it as IDA
    finding none.
    """
    described = _docstring("static_strings")
    assert "Answers with items" in described
    assert "no strings field" in described
    assert "no text field" in described
    assert "value" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _strings")
    chunk = worker[start : worker.index("def _decompile", start)]
    assert '"items": items' in chunk
    assert '"value": value[:max_length]' in chunk
    assert '"strings":' not in chunk
    assert '"text":' not in chunk

def test_static_disassemble_description_names_instructions() -> None:
    """The live catalog omitted the instruction-list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    disasm.data['instructions']. The worker returns instructions with ea,
    size and text, and no items or disassembly field. A caller looking for
    items after a successful disassemble reads it as IDA finding none.
    """
    described = _docstring("static_disassemble")
    joined = " ".join(described.split())
    assert "Answers with instructions" in joined
    assert "no items field" in joined
    assert "no disassembly field" in joined
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _disassemble")
    chunk = worker[start : worker.index("def _xref_type_name", start)]
    assert '"instructions": instructions' in chunk
    assert '"items":' not in chunk
    assert '"disassembly":' not in chunk

