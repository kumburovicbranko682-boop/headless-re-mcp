"""Edge-branch coverage for unpack OEP observation helpers (no live debugger).

Complements ``test_unpack_observe.py`` (happy-path diffs) with the pure-helper
guard branches: rejected region geometry, ``protect_name`` string parsing, and
the skip/fallback arcs inside ``collect_oep_observations``.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.unpack.observe import (
    clip_address_to_module,
    collect_oep_observations,
    find_region_at,
    index_regions_by_base,
    overlaps_module,
    region_base,
    region_covers,
    region_protect,
    region_size,
    stub_rva_ranges_from_sections,
)

_PAGE_READONLY = 0x02
_PAGE_READWRITE = 0x04
_PAGE_EXECUTE = 0x10
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40

MODULE_BASE = 0x140000000
MODULE_SIZE = 0x4000
MODULE_END = MODULE_BASE + MODULE_SIZE


def _region(
    base: int,
    size: int,
    protect: int | None = None,
    *,
    protect_name: str | None = None,
) -> dict[str, Any]:
    region: dict[str, Any] = {"base": base, "size": size}
    if protect is not None:
        region["protect"] = protect
    if protect_name is not None:
        region["protect_name"] = protect_name
    return region


def test_region_base_rejects_non_int_and_negative() -> None:
    assert region_base({"base": "0x1000"}) is None
    assert region_base({"base": -1}) is None
    assert region_base({}) is None
    assert region_base({"base": 0}) == 0


def test_region_size_rejects_non_positive_and_non_int() -> None:
    assert region_size({"size": 0}) is None
    assert region_size({"size": -8}) is None
    assert region_size({"size": "big"}) is None
    assert region_size({"size": 4}) == 4


@pytest.mark.parametrize(
    ("protect_name", "expected"),
    [
        ("EXECUTE_READWRITE", _PAGE_EXECUTE_READWRITE),
        ("execute_read", _PAGE_EXECUTE_READ),
        ("execute", _PAGE_EXECUTE),
        ("writecopy", _PAGE_READWRITE),
        ("readonly", _PAGE_READONLY),
    ],
)
def test_region_protect_maps_protect_name(protect_name: str, expected: int) -> None:
    assert region_protect({"protect_name": protect_name}) == expected


def test_region_protect_none_and_integer_precedence() -> None:
    assert region_protect({}) is None
    assert region_protect({"protect_name": "none"}) is None
    assert region_protect({"protect_name": "guard-only"}) is None
    assert region_protect({"protect": 5, "protect_name": "execute"}) == 5
    assert region_protect({"protect": -1, "protect_name": "execute"}) == _PAGE_EXECUTE


def test_region_covers_requires_base_and_size() -> None:
    assert region_covers({"size": 0x100}, 0x10) is False
    assert region_covers({"base": 0x1000}, 0x1000) is False
    assert region_covers({"base": 0x1000, "size": 0x100}, 0x1050) is True
    assert region_covers({"base": 0x1000, "size": 0x100}, 0x2000) is False


def test_find_region_at_skips_non_covering_then_returns_none() -> None:
    regions = [
        {"base": 0x1000, "size": 0x100},
        {"base": 0x5000, "size": 0x100},
    ]
    assert find_region_at(regions, 0x9999) is None
    assert find_region_at(regions, 0x5050) == {"base": 0x5000, "size": 0x100}


def test_index_regions_by_base_skips_invalid_base() -> None:
    regions = [
        {"base": -1, "size": 0x10},
        {"base": 0x2000, "size": 0x10},
    ]
    indexed = index_regions_by_base(regions)
    assert set(indexed) == {0x2000}


def test_overlaps_module_false_paths() -> None:
    assert overlaps_module({"size": 0x10}, 0x1000, 0x100) is False
    assert overlaps_module({"base": 0x1000, "size": 0x10}, 0x1000, 0) is False
    assert overlaps_module({"base": 0x1000, "size": 0x100}, 0x1050, 0x100) is True


def test_clip_address_to_module_bounds() -> None:
    assert clip_address_to_module(0x1000, 0x1000, 0) is None
    assert clip_address_to_module(0x5000, 0x1000, 0x100) is None
    assert clip_address_to_module(0x1050, 0x1000, 0x100) == 0x1050


def test_stub_rva_ranges_skips_invalid_geometry() -> None:
    ranges = stub_rva_ranges_from_sections(
        [
            {"name": "vmp0", "virtual_address": "nope", "virtual_size": 0x100},
            {"name": "vmp1", "virtual_address": 0x1000, "virtual_size": 0},
            {"name": "vmp2", "virtual_address": 0x2000, "virtual_size": 0x100},
        ]
    )
    assert ranges == [(0x2000, 0x100)]


def test_diff_skips_region_outside_module() -> None:
    outside = _region(MODULE_END + 0x1000, 0x1000, _PAGE_EXECUTE_READ)
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=[outside],
        previous_regions=[],
    )
    assert observations == []


def test_diff_skips_region_without_protect() -> None:
    unknown = _region(MODULE_BASE, MODULE_SIZE)
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=[unknown],
        previous_regions=[],
    )
    assert observations == []


def test_diff_new_nonexecutable_region_emits_nothing() -> None:
    writable = _region(MODULE_BASE, MODULE_SIZE, _PAGE_READWRITE)
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=[writable],
        previous_regions=[],
    )
    assert observations == []


def test_diff_protect_change_without_entry_point_skips_ep_observation() -> None:
    previous = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_READWRITE)]
    current = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ)]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous,
    )
    kinds = {item["kind"] for item in observations}
    assert "ep_section_protect_changed" not in kinds
    assert "write_to_execute" in kinds


def test_diff_readonly_to_exec_emits_new_executable_region() -> None:
    previous = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_READONLY)]
    current = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ)]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous,
    )
    kinds = [item["kind"] for item in observations]
    assert "new_executable_region" in kinds
    assert "write_to_execute" not in kinds
    neo = next(item for item in observations if item["kind"] == "new_executable_region")
    assert neo["previous_protect"] == _PAGE_READONLY


def test_diff_exec_to_exec_protect_change_emits_nothing() -> None:
    previous = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ)]
    current = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READWRITE)]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous,
    )
    assert observations == []


def test_rip_in_non_executable_region_still_checks_stub() -> None:
    regions = [_region(MODULE_BASE, MODULE_SIZE, _PAGE_READWRITE)]
    rip = MODULE_BASE + 0x1500
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=rip,
        regions=regions,
        stub_rva_ranges=((0x3000, 0x1000),),
    )
    kinds = {item["kind"] for item in observations}
    assert "rip_in_main_module_code" not in kinds
    assert "left_stub_region" in kinds


def test_rip_weak_signal_without_region_map() -> None:
    rip = MODULE_BASE + 0x500
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=rip,
        regions=(),
    )
    assert observations == [{"kind": "rip_in_main_module_code", "rip": rip}]


def test_imports_hint_falls_back_to_entry_point() -> None:
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=None,
        entry_point_rva=0x800,
        imports_resolved_hint=True,
    )
    hints = [item for item in observations if item["kind"] == "imports_resolved"]
    assert len(hints) == 1
    assert hints[0]["address"] == MODULE_BASE + 0x800


def test_imports_hint_without_anchor_emits_nothing() -> None:
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=None,
        entry_point_rva=None,
        imports_resolved_hint=True,
    )
    assert observations == []
