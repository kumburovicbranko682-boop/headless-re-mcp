"""ghidra.analyze must name the fields the client actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.ghidra.client import GhidraClient
from headless_re_mcp.core import service_ext
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


def test_ghidra_export_tools_name_the_artifact_they_register() -> None:
    """The export tools kept the raw JSON but the catalog never named it.

    GhidraClient._export_unlocked adds export_path and project_dir to every
    functions/symbols/xrefs/decompile payload, and the service registers that
    export and stamps artifact_id -- the same artifact_id every other
    artifact-producing tool here documents (proxy.export_har, web.screenshot).
    All three reach the caller, so a caller that wanted to reopen the full
    export with artifacts.read had no field naming it. Pin that the client
    still produces the paths, the service still registers the id, and the four
    export docstrings name all three.
    """
    client_src = Path(GhidraClient._export_unlocked.__code__.co_filename).read_text(
        encoding="utf-8"
    )
    export_chunk = client_src[client_src.index("def _export_unlocked") :]
    assert 'payload["export_path"]' in export_chunk
    assert 'payload["project_dir"]' in export_chunk

    service_src = Path(service_ext.__file__).read_text(encoding="utf-8")
    assert 'data["artifact_id"] = art["id"]' in service_src

    for name in ("ghidra.functions", "ghidra.symbols", "ghidra.xrefs", "ghidra.decompile"):
        doc = _tool_docstring(name)
        assert "export_path" in doc, name
        assert "project_dir" in doc, name
        assert "artifact_id" in doc, name


def test_ghidra_decompile_names_the_resolved_function() -> None:
    """decompile resolves the address to a containing function and names it.

    ExportJson.py's decompile branch emits function and entry (the resolved
    function and its entry point) whenever a function contains the address --
    primary output, since the requested address may sit inside the body rather
    than at its entry -- but the catalog named only decompiled/found/truncated.
    """
    script = (
        Path(service_ext.__file__).parents[1]
        / "backends"
        / "ghidra"
        / "scripts"
        / "ExportJson.py"
    ).read_text(encoding="utf-8")
    decompile_branch = script[script.index('mode == "decompile"') :]
    assert 'payload["function"]' in decompile_branch
    assert 'payload["entry"]' in decompile_branch

    doc = _tool_docstring("ghidra.decompile")
    assert "function and entry" in doc
