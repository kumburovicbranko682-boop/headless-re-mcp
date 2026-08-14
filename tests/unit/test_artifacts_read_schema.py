"""artifacts.read must refuse a negative offset at the tool schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def test_artifacts_read_schema_refuses_a_negative_offset() -> None:
    """The catalog accepted a negative byte offset.

    Measured: input schema offset has no minimum. The reader clamps with
    max(0, int(offset)) then seeks, so offset=-1 is answered as the start of
    the file with ok true. An overnight pager that walked backwards then
    treated those bytes as the tail it asked for silently reread the header.
    """
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "artifacts.read"
    )
    props = input_schema_for(handler)["properties"]
    assert props["offset"]["minimum"] == 0
    assert props["offset"]["default"] == 0
