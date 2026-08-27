"""Unpack plans and route recommendations must not advertise phantom tools.

``build_unpack_plan`` hands the caller a list of ``steps`` (each naming a
``tool``) and a ``suggested_tools`` list, and ``recommend_unpack_route`` emits
its own ``suggested_tools``. Those names are the concrete instruction "run this
tool next". If any of them is not a real catalog tool -- e.g. after a tool is
renamed in ``tools/catalog.py`` and one of these hand-maintained tables is not
updated -- the plan quietly tells the operator to run something that does not
exist. ``test_unpack_plan_routes.py`` pins the step *ids* and one fixed
``suggested_tools`` list, but nothing has been cross-checking the tool *names*
against the catalog, so that drift would ship silently.

This locks the invariant across every route the builder and recommender can
take. The catalog exposes all names before any handler is bound, so the guard
stays cheap.
"""

from __future__ import annotations

from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport
from headless_re_mcp.unpack.plan import build_unpack_plan
from headless_re_mcp.unpack.recommend import (
    _ALLOWED_FORCE_ROUTES,
    recommend_unpack_route,
)

# Detection candidate sets chosen to drive each detection-based arm of the
# recommender: UPX, a non-UPX generic packer, a .NET protector (name-matched),
# a VM protector (name-matched), and a stealth-profile protector that prepends
# the stealth-first tools. Combined with every force_route and the two PE flag
# paths below, this reaches every place either module emits a tool name.
_CANDIDATE_ROUTES: tuple[list[dict[str, object]], ...] = (
    [{"category": "packer", "name": "UPX", "summary": "upx 4.x packed", "confidence": 0.9}],
    [{"category": "protector", "name": "Custom", "summary": "unknown protector"}],
    [{"category": "packer", "name": "ConfuserEx", "summary": ".net reactor stub"}],
    [{"category": "protector", "name": "VMProtect", "summary": "vmprotect 3.x stub"}],
    [{"category": "protector", "name": "Themida", "summary": "themida vmp guard"}],
    [],
)


def _catalog_tool_names() -> frozenset[str]:
    return frozenset(spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP))


def _plans() -> list[dict[str, object]]:
    plans: list[dict[str, object]] = []
    for route in sorted(_ALLOWED_FORCE_ROUTES):
        plans.append(build_unpack_plan([], force_route=route))
    plans.append(build_unpack_plan([], pe_dotnet=True))
    plans.append(build_unpack_plan([], pe_vm_like=True))
    for candidates in _CANDIDATE_ROUTES:
        plans.append(build_unpack_plan(candidates))
    return plans


def test_every_planned_step_names_a_real_catalog_tool() -> None:
    catalog = _catalog_tool_names()
    offenders: dict[str, set[str]] = {}
    for plan in _plans():
        steps = plan["steps"]
        assert isinstance(steps, list)
        for step in steps:
            tool = step["tool"]
            if tool not in catalog:
                offenders.setdefault(str(plan["route"]), set()).add(str(tool))
    assert not offenders, f"unpack plan steps name tools absent from the catalog: {offenders}"


def test_every_suggested_tool_is_a_real_catalog_tool() -> None:
    catalog = _catalog_tool_names()
    offenders: set[str] = set()

    for plan in _plans():
        suggested = plan["suggested_tools"]
        assert isinstance(suggested, list)
        offenders.update(str(tool) for tool in suggested if tool not in catalog)

    for candidates in _CANDIDATE_ROUTES:
        recommendation = recommend_unpack_route(candidates)
        offenders.update(
            tool for tool in recommendation.suggested_tools if tool not in catalog
        )
    for route in sorted(_ALLOWED_FORCE_ROUTES):
        recommendation = recommend_unpack_route([], force_route=route)
        offenders.update(
            tool for tool in recommendation.suggested_tools if tool not in catalog
        )

    assert not offenders, f"suggested_tools name tools absent from the catalog: {sorted(offenders)}"
