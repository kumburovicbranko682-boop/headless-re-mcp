"""unpack.iat.scan must refuse an oversized candidate budget at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.unpack import build_unpack_tools


def test_unpack_iat_scan_schema_caps_max_candidates() -> None:
    """The catalog accepted any max_candidates integer.

    Measured: input schema max_candidates has no minimum or maximum.
    unpack_iat_scan inflates the budget to max(n * 3, 24) before imports_scan,
    whose native ReadUnsigned already refuses anything above 32
    (MaxImportCandidates). A caller that sent a huge n occupied a worker
    until that native refuse, and a non-positive n still reached ranking.
    """
    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    assert "MaxImportCandidates = 32" in header
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    start = service.index("def unpack_iat_scan")
    chunk = service[start : start + 2500]
    assert "max_candidates=max(max_candidates * 3, 24)" in chunk
    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == "unpack.iat.scan"
    )
    props = input_schema_for(handler)["properties"]
    assert props["max_candidates"]["minimum"] == 1
    assert props["max_candidates"]["maximum"] == 32
    assert props["max_candidates"]["default"] == 8


def test_unpack_iat_scan_schema_exposes_mode_as_an_enum() -> None:
    """mode delegates to imports_scan yet the tool typed it as a bare str.

    unpack.iat.scan forwards mode to AnalysisService.imports_scan, whose guard
    (and the native ScanImports guard) accept only all|consecutive|sparse|
    call_site. Typed as ``str`` the schema offered the agent no hint, so a wrong
    mode reached the service only to come back invalid_params. The schema must
    advertise the closed set as an enum, identical to imports.scan since both
    share tools.limits.ImportScanMode.
    """
    from typing import get_args

    from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools
    from headless_re_mcp.tools.limits import ImportScanMode

    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == "unpack.iat.scan"
    )
    mode = input_schema_for(handler)["properties"]["mode"]

    assert set(mode["enum"]) == set(get_args(ImportScanMode))
    assert mode["default"] == "all"

    # The two IAT-scan surfaces must not drift: same enum on both.
    imports_scan = next(
        binding.handler
        for binding in build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
        if binding.name == "imports.scan"
    )
    assert (
        input_schema_for(imports_scan)["properties"]["mode"]["enum"] == mode["enum"]
    )
