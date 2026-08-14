"""unpack.vmp.dump must name the dump fields it actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.unpack import build_unpack_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_unpack_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_unpack_vmp_dump_names_output_path_not_dump() -> None:
    """The live catalog mentioned dump_ok in prose and omitted the payload nest.

    tests/unit/test_m7_external_adapters.py already reads data['dump_ok'] and
    data['claims_universal_unpack']. The service returns vmp_dumper,
    output_path, dump_ok, imports_rebuilt, vm_restored and
    claims_universal_unpack false. There is no dump field. A caller looking
    for dump after a successful VMPDump reads the artifact as missing.
    """
    described = " ".join(_tool_docstring("unpack.vmp.dump").split())
    assert "Answers with vmp_dumper, output_path, dump_ok" in described
    assert "claims_universal_unpack false" in described
    assert "no dump field" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    start = source.index("def unpack_vmp_dump")
    chunk = source[start : source.index("def unpack_scylla_rebuild", start)]
    assert '"vmp_dumper": result.to_dict()' in chunk
    assert '"output_path": str(result.output_path)' in chunk
    assert '"dump_ok": result.dump_ok' in chunk
    assert '"claims_universal_unpack": False' in chunk
    assert '"dump":' not in chunk
