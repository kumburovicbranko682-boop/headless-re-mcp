"""unpack.score_oep must refuse an oversized candidate budget at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.unpack import build_unpack_tools


def test_unpack_score_oep_schema_caps_max_candidates() -> None:
    """The catalog accepted any max_candidates integer.

    Measured: input schema max_candidates has no minimum or maximum.
    score_oep refuses non-positive values only after the worker starts, then
    keeps every scored row when the budget is huge. Native import ranking
    already caps the same budget at 32 (MaxImportCandidates), so an overnight
    caller that sent 10_000_000 occupied a worker building a list that the
    native side would never have allowed.
    """
    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    assert "MaxImportCandidates = 32" in header
    oep = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "unpack"
        / "oep.py"
    ).read_text(encoding="utf-8")
    assert "if max_candidates <= 0:" in oep
    assert "candidates = candidates[:max_candidates]" in oep
    handler = next(
        binding.handler
        for binding in build_unpack_tools(object())  # type: ignore[arg-type]
        if binding.name == "unpack.score_oep"
    )
    props = input_schema_for(handler)["properties"]
    assert props["max_candidates"]["minimum"] == 1
    assert props["max_candidates"]["maximum"] == 32
    assert props["max_candidates"]["default"] == 8
