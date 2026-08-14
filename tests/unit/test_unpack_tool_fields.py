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

def test_unpack_scylla_rebuild_names_output_path() -> None:
    """The live catalog omitted output_path and the unpack-claim flag.

    tests/unit/test_m7_external_adapters.py already reads result.data['output_path'],
    data['input_unchanged'] and data['claims_universal_unpack'] on the Scylla
    path. A caller that treats a successful IAT rebuild as a universal unpack
    never sees the false flag.
    """
    described = " ".join(_tool_docstring("unpack.scylla.rebuild").split())
    assert "Answers with scylla" in described
    assert "output_path" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert '"scylla": result.to_dict()' in source

def test_unpack_auto_names_status_not_a_boolean() -> None:
    """The live catalog omitted the status field.

    tests/unit/test_unpack_auto.py already reads result.data['status']
    (not_upx / unpacked) and data['claims_universal_unpack']. A caller looking
    for a boolean unpacked flag after a successful not_upx route reads it as
    a finished unpack.
    """
    described = " ".join(_tool_docstring("unpack.auto").split())
    assert "Answers with status" in described
    assert "not a boolean" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert 'payload["status"] = "not_upx"' in source
    assert 'payload["status"] = "unpacked"' in source

def test_unpack_plan_names_plan_not_routes() -> None:
    """The live catalog omitted the plan object.

    tests/unit/test_m5_unpack_session.py already reads planned.data['plan']['route'].
    The service returns plan, recommendation, pe_vm_like, force_route and
    claims_universal_unpack, and has no routes field. A caller looking for
    routes after a successful plan reads it as no unpack path existing.
    """
    described = " ".join(_tool_docstring("unpack.plan").split())
    assert "Answers with plan" in described
    assert "no routes field" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    start = source.index("def unpack_plan")
    chunk = source[start : source.index("def unpack_start", start)]
    assert '"plan": plan' in chunk
    assert '"routes"' not in chunk

def test_unpack_status_nests_state_under_unpack() -> None:
    """The live catalog omitted the unpack object.

    unpack_status returns unpack (state.to_dict) and claims_universal_unpack.
    There is no top-level status or timeline field. A caller looking for
    timeline after a successful status call reads an active session as idle.
    """
    described = " ".join(_tool_docstring("unpack.status").split())
    assert "Answers with unpack" in described
    assert "no status or timeline field" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    start = source.index("def unpack_status")
    chunk = source[start : source.index("def unpack_cancel", start)]
    assert '{"unpack": state.to_dict(), "claims_universal_unpack": False}' in chunk
    assert '"timeline"' not in chunk

def test_unpack_start_nests_state_under_unpack() -> None:
    """The live catalog omitted the unpack object.

    tests/unit/test_m5_unpack_session.py already reads started.data['unpack']['phase']
    and deadline_at. The service returns unpack plus claims_universal_unpack, and
    has no top-level session field. A caller looking for session after a
    successful start reads the run as not having begun.
    """
    described = " ".join(_tool_docstring("unpack.start").split())
    assert "Answers with unpack" in described
    assert "no session field" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    assert '"unpack": state.to_dict()' in source

def test_unpack_artifacts_names_artifacts_not_items() -> None:
    """The live catalog omitted the artifacts array.

    tests/unit/test_m5_unpack_session.py already reads arts.data['count'] and
    data['timeline_path']. The service returns artifacts, count, timeline_path,
    state_path and claims_universal_unpack, and has no items field. A caller
    looking for items after a successful list reads dumps as missing.
    """
    described = " ".join(_tool_docstring("unpack.artifacts").split())
    assert "Answers with artifacts" in described
    assert "no items field" in described
    assert "timeline_path" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    start = source.index("def unpack_artifacts")
    chunk = source[start : start + 1200]
    assert '"artifacts": [item.to_dict() for item in state.artifacts]' in chunk
    assert '"items"' not in chunk

def test_unpack_dump_module_names_output_path() -> None:
    """The live catalog omitted output_path and the unpack-claim flag.

    tests/unit/test_m4_unpack_service.py already reads dumped.data['output_path'].
    The service copies the dump payload, sets claims_universal_unpack false, and
    has no dump field. A caller looking for dump after a successful write reads
    the file as missing.
    """
    described = " ".join(_tool_docstring("unpack.dump_module").split())
    assert "Answers with output_path" in described
    assert "no dump field" in described
    assert "claims_universal_unpack false" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    start = source.index("def unpack_dump_module")
    chunk = source[start : source.index("def unpack_stub_coupling", start)]
    assert 'payload["claims_universal_unpack"] = False' in chunk
    assert 'output_path = str(payload.get("output_path"' in chunk

