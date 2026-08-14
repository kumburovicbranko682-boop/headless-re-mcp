"""artifacts.gc must refuse a zero or negative budget at the tool schema."""

from __future__ import annotations

from headless_re_mcp.core.retention import DEFAULT_MAX_TOTAL_BYTES
from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def test_artifacts_gc_schema_refuses_a_zero_budget() -> None:
    """The catalog accepted max_total_bytes of 0.

    Measured: input schema max_total_bytes has no minimum. gc_artifacts
    deletes oldest-first while total > budget, so 0 (or a negative budget)
    removes every registered file except the newest. An overnight caller that
    meant to keep the 512 MiB default and passed 0 instead wipes the tree
    and the tool still answers ok.
    """
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "artifacts.gc"
    )
    props = input_schema_for(handler)["properties"]
    assert props["max_total_bytes"]["minimum"] == 1
    assert props["max_total_bytes"]["default"] == DEFAULT_MAX_TOTAL_BYTES
    assert "maximum" not in props["max_total_bytes"]
