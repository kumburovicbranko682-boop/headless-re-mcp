"""ghidra.analyze must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.backends.ghidra.mapping import _ITEM_ADDRESS_FIELDS
from headless_re_mcp.tools.ghidra import build_ghidra_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_ghidra_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_ghidra_analyze_puts_the_log_in_stdout_excerpt_not_functions() -> None:
    """The catalog said analysis and never named the payload.

    Measured against GhidraClient.analyze_binary: success is project_dir,
    stdout_excerpt and note. There is no functions or analysis field. Looking
    for functions after a successful analyze reads as Ghidra finding none,
    and the minutes spent do not populate the other ghidra tools.
    """
    source = Path(GhidraClient.analyze_binary.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def analyze_binary")
    chunk = source[start : source.index("def functions", start)]
    returned = chunk[chunk.rindex("return {") :]
    assert '"stdout_excerpt"' in returned
    assert '"project_dir"' in returned
    assert '"note"' in returned
    assert '"functions"' not in returned
    assert '"analysis"' not in returned
    described = _tool_docstring("ghidra.analyze")
    assert "Answers with project_dir" in described
    assert "stdout_excerpt" in described
    assert "project_dir" in described
    assert "no functions field" in described
    assert "no analysis field" in described


def test_ghidra_list_docstrings_name_the_coordinate_companions() -> None:
    """The {module, rva, va, architecture} objects both engines now emit are
    discoverable only through the tool descriptions, so each companion key must
    be named where the model reads it -- and named the same string the mapper
    actually adds, so the doc cannot drift from ``enrich_ghidra_payload``. The
    keys are sourced from _ITEM_ADDRESS_FIELDS to keep the two in lockstep.
    """
    docs = {
        "functions": _tool_docstring("ghidra.functions"),
        "symbols": _tool_docstring("ghidra.symbols"),
        "xrefs": _tool_docstring("ghidra.xrefs"),
    }
    for mode, fields in _ITEM_ADDRESS_FIELDS.items():
        doc = docs[mode]
        for _source_field, object_field in fields:
            assert object_field in doc, (mode, object_field)

    # decompile's companion is the top-level entry_address the mapper attaches.
    assert "entry_address" in _tool_docstring("ghidra.decompile")

    # functions is where the shared coordinate frame is spelled out: the rva
    # coordinate and the top-level module/image_base/architecture triple.
    functions = docs["functions"]
    assert "rva" in functions
    assert "image_base" in functions
    assert "architecture" in functions
