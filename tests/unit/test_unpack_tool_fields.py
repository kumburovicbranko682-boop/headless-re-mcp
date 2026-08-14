"""unpack.upx.test must name the fields the service actually returns."""

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


def test_unpack_upx_test_nests_cli_result_under_upx() -> None:
    """The live catalog omitted the nested CLI result.

    service_unpack_cli.unpack_upx_test returns upx (UpxResult.to_dict) and
    input_unchanged. A caller looking for top-level stdout or ok-inside-data
    after a successful test reads it as UPX returning nothing.
    """
    described = " ".join(_tool_docstring("unpack.upx.test").split())
    assert "Answers with upx" in described
    assert "input_unchanged" in described
    assert "no top-level stdout field" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert '{"upx": result.to_dict(), "input_unchanged": True}' in source

def test_unpack_upx_unpack_names_output_path_and_refuses_universal() -> None:
    """The live catalog omitted output_path and the unpack-claim flag.

    tests/unit/test_upx_fixtures.py already reads unpacked.data['die_rescan'],
    data['claims_universal_unpack'] and data['input_unchanged']. A caller that
    treats a successful upx -d as a universal unpack never sees the false flag.
    """
    described = " ".join(_tool_docstring("unpack.upx.unpack").split())
    assert "Answers with upx" in described
    assert "output_path" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert '"output_path": str(result.output_path)' in source
    assert '"claims_universal_unpack": False' in source

def test_unpack_external_probe_names_per_tool_status() -> None:
    """The live catalog omitted the per-tool status objects.

    tests/unit/test_m7_external_adapters.py already reads probed.data['xvlkc'],
    data['vmp_dumper'], data['scylla'] and data['claims_universal_unpack'].
    A caller looking for a top-level ready flag after a successful probe reads
    missing tools as if the probe returned nothing.
    """
    described = " ".join(_tool_docstring("unpack.external.probe").split())
    assert "Answers with xvlkc" in described
    assert "vmp_dumper" in described
    assert "scylla" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert '"xvlkc": xvlkc_status' in source
    assert '"vmp_dumper": vmp_status' in source
    assert '"scylla": scylla_status' in source

def test_unpack_xvlkc_unpack_names_output_path() -> None:
    """The live catalog omitted output_path and the unpack-claim flag.

    tests/unit/test_m7_external_adapters.py already reads result.data['output_path']
    and data['claims_universal_unpack'] on the XVLKC path. A caller that treats a
    successful XVLKC run as a universal unpack never sees the false flag.
    """
    described = " ".join(_tool_docstring("unpack.xvlkc.unpack").split())
    assert "Answers with xvlkc" in described
    assert "output_path" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert '"xvlkc": result.to_dict()' in source
    assert '"output_path": str(result.output_path)' in source

