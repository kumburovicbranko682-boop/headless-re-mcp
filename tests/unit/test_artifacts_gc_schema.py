"""artifacts.gc must refuse a zero or negative budget at the tool schema."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core.models import Result
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


def test_artifacts_gc_handler_forwards_the_budget_and_dumps_the_envelope() -> None:
    """The bound handler passes max_total_bytes through and returns a dict."""

    class _Service:
        def artifacts_gc(self, *, max_total_bytes: int) -> Result[dict[str, Any]]:
            return Result(ok=True, data={"budget": max_total_bytes})

    handler = next(
        binding.handler
        for binding in build_meta_tools(_Service())  # type: ignore[arg-type]
        if binding.name == "artifacts.gc"
    )
    envelope = handler(max_total_bytes=1024)
    assert envelope["ok"] is True
    assert envelope["data"]["budget"] == 1024
