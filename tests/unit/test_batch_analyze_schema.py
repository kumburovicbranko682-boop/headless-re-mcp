"""batch.analyze must refuse an oversized binaries list at the tool schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def test_batch_analyze_schema_matches_service_path_cap() -> None:
    """The catalog accepted an unbounded binaries list.

    Measured: input schema binaries has no maxItems. The service refuses more
    than 32 paths before opening any session. A caller that submits hundreds
    of samples still occupies a worker until that check runs, and overnight
    intake retries the same oversized batch as if it never arrived.
    """
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "batch.analyze"
    )
    props = input_schema_for(handler)["properties"]
    assert props["binaries"]["minItems"] == 1
    assert props["binaries"]["maxItems"] == 32
