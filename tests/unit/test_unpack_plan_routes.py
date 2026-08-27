"""Route coverage for the M5 unpack plan builder.

``test_m5_unpack_session.py`` already exercises the ``upx`` and ``dotnet``
arms. This pins the remaining dynamic arms (``bounded_dynamic`` and
``generic_dynamic``) plus the explicit ``recommendation=`` short-circuit,
asserting the fail-closed honesty flags every plan must carry.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.unpack.plan import build_unpack_plan
from headless_re_mcp.unpack.recommend import UnpackRecommendation


def _step_ids(plan: dict[str, Any]) -> list[str]:
    return [step["id"] for step in plan["steps"]]


def _assert_non_authoritative(plan: dict[str, Any]) -> None:
    assert plan["authoritative"] is False
    assert plan["claims_universal_unpack"] is False
    assert isinstance(plan["notes"], list) and plan["notes"]


def test_bounded_dynamic_route_from_pe_vm_like() -> None:
    plan = build_unpack_plan([], pe_vm_like=True)

    assert plan["route"] == "bounded_dynamic"
    assert plan["backend"] == "m4_bounded"
    ids = _step_ids(plan)
    assert ids[:2] == ["detect", "dynamic_open"]
    assert "iat_validate" in ids
    assert "iat_rebuild" in ids
    assert plan["recoverability_hint"] == "vm_coupled_dump_only"
    _assert_non_authoritative(plan)


def test_generic_dynamic_route_from_unknown_protector() -> None:
    plan = build_unpack_plan(
        [
            {
                "category": "protector",
                "name": "CustomPacker",
                "summary": "unrecognized protector stub",
                "confidence": 0.5,
            }
        ]
    )

    assert plan["route"] == "generic_dynamic"
    assert plan["backend"] == "m4_generic"
    ids = _step_ids(plan)
    assert "pe_rebuild" in ids
    assert "iat_validate" not in ids
    assert plan["candidates"] and plan["candidates"][0]["name"] == "CustomPacker"
    _assert_non_authoritative(plan)


def test_explicit_recommendation_is_used_verbatim() -> None:
    recommendation = UnpackRecommendation(
        route="bounded_dynamic",
        confidence=0.42,
        rationale="caller-supplied routing advice",
        suggested_tools=("unpack.plan", "unpack.start"),
        candidates=({"category": "protector", "name": "PreRouted"},),
        recoverability_hint="vm_coupled_dump_only",
    )

    plan = build_unpack_plan([], recommendation=recommendation)

    assert plan["route"] == "bounded_dynamic"
    assert plan["backend"] == "m4_bounded"
    assert plan["confidence"] == 0.42
    assert plan["rationale"] == "caller-supplied routing advice"
    assert plan["suggested_tools"] == ["unpack.plan", "unpack.start"]
    assert plan["candidates"][0]["name"] == "PreRouted"
    _assert_non_authoritative(plan)
