"""sessions.unclean must refuse a negative offset at the tool schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def test_sessions_unclean_schema_refuses_a_negative_offset() -> None:
    """The catalog accepted a negative page offset.

    Measured: input schema offset has no minimum. The store clamps with
    max(0, int(offset)), so offset=-1 is answered as page 0 with ok true.
    An overnight pager that walked backwards then treated that first page
    as the negative page it asked for silently reread the newest unclean
    sessions.
    """
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "sessions.unclean"
    )
    props = input_schema_for(handler)["properties"]
    assert props["offset"]["minimum"] == 0
    assert props["offset"]["default"] == 0
