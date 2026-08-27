"""session.recover must refuse unknown backend names at the tool schema."""

from __future__ import annotations

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def test_session_recover_schema_matches_recover_backend_names() -> None:
    """The catalog accepted any backends list.

    Measured: input schema backends items have no pattern. _recover_backend_kinds
    accepts ida, static, x64dbg, dynamic, web and proxy. A caller that sends a
    long list of unknown names still occupies a worker until that check runs,
    and overnight recovery retries the same unknown names as if they never
    arrived.
    """
    handler = next(
        binding.handler
        for binding in build_meta_tools(object())  # type: ignore[arg-type]
        if binding.name == "session.recover"
    )
    props = input_schema_for(handler)["properties"]
    items = next(
        item for item in props["backends"]["anyOf"] if item.get("type") == "array"
    )["items"]
    assert items["pattern"] == "^(ida|static|x64dbg|dynamic|web|proxy)$"
