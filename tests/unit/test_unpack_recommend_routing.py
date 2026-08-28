"""Routing branches for the non-authoritative unpack recommender.

``recommend_unpack_route`` maps untrusted detection candidates (and an optional
caller ``force_route``) to a workflow route without executing anything. These
pin the ``force_route`` validation and hint mapping, the PE VM-like synthetic
candidate path, and the ``pe_suggests_vm_protector`` heuristic — all of which
the broader suite left uncovered.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.unpack.recommend import (
    UnpackRecommendation,
    pe_suggests_vm_protector,
    recommend_unpack_route,
)


def test_force_route_upx_maps_to_iat_recoverable_hint() -> None:
    rec = recommend_unpack_route([], force_route=" upx ")
    assert rec.route == "upx"
    assert rec.recoverability_hint == "iat_recoverable"
    assert rec.confidence == 0.5
    assert rec.authoritative is False


def test_force_route_bounded_dynamic_maps_to_dump_only_hint() -> None:
    rec = recommend_unpack_route([], force_route="bounded_dynamic")
    assert rec.route == "bounded_dynamic"
    assert rec.recoverability_hint == "vm_coupled_dump_only"


def test_force_route_none_has_no_recoverability_hint() -> None:
    rec = recommend_unpack_route([], force_route="none")
    assert rec.route == "none"
    assert rec.recoverability_hint is None


def test_force_route_rejects_an_unknown_route() -> None:
    with pytest.raises(ValueError, match="force_route must be one of"):
        recommend_unpack_route([], force_route="magic")


def test_pe_vm_like_without_a_named_vm_adds_a_synthetic_candidate() -> None:
    rec = recommend_unpack_route([], pe_vm_like=True)
    assert rec.route == "bounded_dynamic"
    assert rec.recoverability_hint == "vm_coupled_dump_only"
    # The synthetic protector is surfaced so the caller sees why the route flipped.
    assert any(item.get("source") == "builtin.pe_vm_like" for item in rec.candidates)
    assert rec.confidence == 0.4


def test_named_vm_candidate_does_not_synthesize_and_scores_higher() -> None:
    rec = recommend_unpack_route(
        [{"category": "protector", "name": "VMProtect", "summary": "vmp stub"}],
    )
    assert rec.route == "bounded_dynamic"
    assert rec.confidence == 0.45
    assert not any(item.get("source") == "builtin.pe_vm_like" for item in rec.candidates)


def test_pe_suggests_vm_protector_matches_a_vmp_section_name() -> None:
    assert pe_suggests_vm_protector(section_names=[".vmp0"]) is True


def test_pe_suggests_vm_protector_needs_the_full_anomaly_combo() -> None:
    assert (
        pe_suggests_vm_protector(
            finding_ids=["high-entropy:.text", "sparse-imports", "rwx-section:.data"],
        )
        is True
    )
    # High entropy alone is not enough to claim a VM protector.
    assert pe_suggests_vm_protector(finding_ids=["high-entropy:.text"]) is False


def test_recommendation_serializes_to_a_plain_object() -> None:
    rec = recommend_unpack_route([], force_route="none")
    assert isinstance(rec, UnpackRecommendation)
    payload = rec.to_dict()
    assert payload["route"] == "none"
    assert payload["authoritative"] is False
    assert 0.0 <= payload["confidence"] <= 1.0
