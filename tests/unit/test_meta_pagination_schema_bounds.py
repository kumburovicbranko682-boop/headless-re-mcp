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

The offset+limit shape, though, only sees page readers. It misses the meta
numerics that stand alone -- ``meta.metrics.limit``, ``report.generate.audit_limit``
and ``batch.analyze.max_workers`` (a thread-pool size) -- which are just as
reachable on the schema-skipping transport and just as much a "return / spawn
everything" hazard when unbounded. So a second guard here mirrors the non-PE
line's ``test_every_non_pe_numeric_param_declares_an_upper_bound`` across the
*whole* meta numeric surface, exempting a floored ``offset`` and a fail-closed
allowlist of the genuinely-unbounded ones (``sync.*`` addresses, the
``artifacts.gc`` byte budget).
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


def _meta_numeric_params() -> dict[tuple[str, str], dict[str, Any]]:
    """Map every ``(tool, param)`` on the meta line whose type is integer/number."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for bound in build_meta_tools(cast(Any, object())):
        for param, prop in input_schema_for(bound.handler).get("properties", {}).items():
            if prop.get("type") in ("integer", "number"):
                found[(bound.name, param)] = prop
    return found


# (tool, param) meta numerics that legitimately carry no upper bound, keyed by the
# exact pair (fail-closed): a new unbounded numeric trips the guard until it is
# added here with a reason, rather than passing silently. The mirror of
# _UNBOUNDED_NUMERIC_OK on the non-PE line.
_UNBOUNDED_META_NUMERIC_OK = frozenset(
    {
        # Raw addresses span the whole address space, so a magnitude ceiling is
        # meaningless (the sync layer validates reachability, not size). These
        # are PE-line address-translation tools that happen to live in
        # build_meta_tools; same rationale as frida.memory.read's address.
        ("sync.static_to_runtime", "address"),
        ("sync.runtime_to_static", "address"),
        ("sync.module_preferred_to_runtime", "address"),
        ("sync.module_runtime_to_preferred", "address"),
        ("sync.resolve_runtime_address", "address"),
        # A retention *budget*: artifacts.gc deletes oldest-first until the tree
        # fits under it, so a huge value simply keeps more (GC does less) rather
        # than fetching anything -- unbounded above is safe, like offset. The
        # ge=1 floor already stops a 0/negative budget from wiping everything.
        ("artifacts.gc", "max_total_bytes"),
    }
)


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


def test_scan_reaches_the_standalone_meta_numerics() -> None:
    """Non-vacuity, and the reason this guard exists beyond the sibling above.

    The offset+limit shape guard only sees page readers; it never looks at the
    meta numerics that stand alone -- ``meta.metrics.limit``,
    ``report.generate.audit_limit`` and ``batch.analyze.max_workers`` (a thread-
    pool size, the resource-shaped kind the non-PE numeric guard exists for).
    All three are reachable on the agent / OpenAI-bridge path that skips the
    pydantic schema, so pin that the numeric scan actually reaches them or the
    upper-bound check below could pass on a set that misses exactly these.
    """
    seen = set(_meta_numeric_params())
    assert {
        ("meta.metrics", "limit"),
        ("report.generate", "audit_limit"),
        ("batch.analyze", "max_workers"),
    } <= seen, f"the meta numeric scan looks broken, saw {sorted(seen)}"


def test_every_meta_numeric_param_declares_an_upper_bound() -> None:
    """Every meta numeric must cap, except a floored ``offset`` or an allowlisted one.

    Mirrors ``test_every_non_pe_numeric_param_declares_an_upper_bound`` for the
    meta line, which the non-PE guard never scans. A bare integer with no maximum
    is a "return everything" / "spawn everything" hazard on the schema-skipping
    transport; ``offset`` is exempt (floored, unbounded above by design) and the
    genuinely-unbounded numerics are named in ``_UNBOUNDED_META_NUMERIC_OK``.
    """
    offenders: list[str] = []
    for (tool, param), prop in _meta_numeric_params().items():
        if param == "offset" or (tool, param) in _UNBOUNDED_META_NUMERIC_OK:
            continue
        if not isinstance(prop.get("maximum"), (int, float)):
            offenders.append(f"{tool}.{param} (schema: {prop})")
    assert offenders == [], (
        "these meta numeric params declare no maximum, so a transport skipping the "
        "pydantic schema could hand the backend an absurd page size or resource "
        "count; add a Field(le=...) or, if genuinely unbounded, list the (tool, "
        f"param) in _UNBOUNDED_META_NUMERIC_OK with a reason: {offenders}"
    )
