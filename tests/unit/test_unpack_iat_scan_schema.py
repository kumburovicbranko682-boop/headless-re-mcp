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
