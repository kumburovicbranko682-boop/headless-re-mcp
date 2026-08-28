"""Every meta.* paginated reader must bound its `limit` and floor its `offset`.

The non-PE pagination guard (``test_non_pe_pagination_schema_bounds``) scans the
web / proxy / device / frida / apk / js / workspace builders, but the shared meta
line -- ``artifacts.list``, ``artifacts.read``, ``timeline.list``,
``sessions.unclean``, ``audit.list``, ``knowledge.query`` -- lives in
``build_meta_tools``, which that guard never scans. Those readers page over
stores that only grow (registered artifacts, audit rows, per-session timeline
files, unclean-session rows, the knowledge base), so an unbounded ``limit`` on
the agent / OpenAI-bridge path -- which calls the handler directly and skips the
pydantic schema -- is exactly the "return everything" fetch the sibling guard was
built to prevent, just on a surface it never watched. The store layer clamps as a
backstop (``max(1, min(int(limit), MAX))``), but the schema bound is the
fail-fast, advertised half of that contract and it was going unenforced here.

``build_meta_tools`` cannot simply be added to the sibling guard: it also bundles
PE-line address-translation tools (``sync.*``) whose ``address`` params are
unbounded by design, which would pull PE concerns into a "non-PE" guard. So a
meta reader is identified structurally instead -- by taking BOTH an ``offset``
and a ``limit`` -- which selects the real page readers, catches a new one without
naming it, and excludes the ``sync.*`` address and ``artifacts.gc`` budget tools
that are not page readers by that same shape.
"""

from __future__ import annotations

from typing import Any, cast

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.meta import build_meta_tools


def _meta_paginated_readers() -> dict[str, dict[str, dict[str, Any]]]:
    """Map each meta tool taking BOTH offset and limit to those two schemas.

    ``input_schema_for`` reads the handler signature alone, so a dummy service
    stands in for ``analysis`` and no backend is needed.
    """
    found: dict[str, dict[str, dict[str, Any]]] = {}
    for bound in build_meta_tools(cast(Any, object())):
        props = input_schema_for(bound.handler).get("properties", {})
        if "offset" in props and "limit" in props:
            found[bound.name] = {"offset": props["offset"], "limit": props["limit"]}
    return found


def test_scan_reaches_the_known_meta_readers() -> None:
    """Non-vacuity: the growing-store readers must be in the scan, or a broken
    enumeration would let the bounds checks below pass on an empty set."""
    readers = set(_meta_paginated_readers())
    assert {
        "artifacts.list",
        "timeline.list",
        "sessions.unclean",
        "audit.list",
        "knowledge.query",
    } <= readers, f"the meta paginated-reader scan looks broken, saw {sorted(readers)}"


def test_every_meta_reader_bounds_its_limit() -> None:
    for name, params in _meta_paginated_readers().items():
        limit = params["limit"]
        assert limit.get("type") == "integer", f"{name}: limit must be an integer, got {limit}"
        assert limit.get("minimum") == 1, (
            f"{name}: limit minimum must be 1, got {limit.get('minimum')}"
        )
        maximum = limit.get("maximum")
        assert isinstance(maximum, int) and maximum >= 1, (
            f"{name}: limit must declare a positive maximum -- a transport skipping "
            f"the schema would treat a bare int page size as 'return everything' over "
            f"a store that only grows; got {maximum}"
        )


def test_every_meta_reader_floors_its_offset() -> None:
    for name, params in _meta_paginated_readers().items():
        offset = params["offset"]
        assert offset.get("type") == "integer", f"{name}: offset must be an integer, got {offset}"
        assert offset.get("minimum") == 0, (
            f"{name}: offset minimum must be 0, got {offset.get('minimum')}"
        )
