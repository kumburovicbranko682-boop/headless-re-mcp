"""ghidra.analyze must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.ghidra.client import _SCRIPT_DIR, GhidraClient
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


def test_export_script_reads_args_via_getscriptargs() -> None:
    """ExportJson reads postScript args through getScriptArgs(), not a bare ARGS.

    Ghidra's Jython injects currentProgram/monitor but never a bare ``ARGS``
    global, so ``mode = ARGS[0]`` raised NameError and left the export unwritten
    -- every ghidra.functions/symbols/xrefs/decompile then failed with "export
    JSON missing after postScript". The subprocess-mocked adapter suite cannot
    see this because only a live analyzeHeadless runs the file, so pin the real
    API here: ARGS must be assigned from getScriptArgs() before it is read.
    """
    tree = ast.parse((_SCRIPT_DIR / "ExportJson.py").read_text(encoding="utf-8"))
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "getScriptArgs" in calls, "ExportJson must read args via getScriptArgs()"
    references = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "ARGS"]
    assert references, "ExportJson should define ARGS from getScriptArgs()"
    first = min(references, key=lambda n: (n.lineno, n.col_offset))
    assert isinstance(first.ctx, ast.Store), "ARGS must be assigned before it is read"
