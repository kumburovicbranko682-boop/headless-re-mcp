"""Unit tests for unpack OEP observation collectors (no live debugger)."""

from __future__ import annotations

import pytest

from headless_re_mcp.unpack.observe import (
    collect_oep_observations,
    find_region_at,
    index_regions_by_base,
    is_executable_protect,
    is_writable_protect,
    region_base,
    region_protect,
    region_size,
    stub_rva_ranges_from_sections,
)
from headless_re_mcp.unpack.oep import score_oep_candidates

_PAGE_READWRITE = 0x04
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40

MODULE_BASE = 0x140000000
MODULE_SIZE = 0x4000


def _region(
    base: int,
    size: int,
    protect: int,
    *,
    protect_name: str | None = None,
) -> dict[str, object]:
    return {
        "base": base,
        "size": size,
        "protect": protect,
        "protect_name": protect_name,
    }


def test_protect_helpers() -> None:
    assert is_executable_protect(_PAGE_EXECUTE_READ)
    assert is_writable_protect(_PAGE_READWRITE)
    assert is_writable_protect(_PAGE_EXECUTE_READWRITE)
    assert not is_executable_protect(_PAGE_READWRITE)


def test_stub_rva_ranges_from_upx_sections() -> None:
    ranges = stub_rva_ranges_from_sections(
        [
            {"name": "UPX0", "virtual_address": 0x1000, "virtual_size": 0x2000},
            {"name": "UPX1", "virtual_address": 0x3000, "virtual_size": 0x1000},
            {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x500},
        ]
    )
    assert ranges == [(0x3000, 0x1000)]


def test_rip_in_main_module_code_and_left_stub() -> None:
    regions = [
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ, protect_name="execute_read")
    ]
    rip = MODULE_BASE + 0x1500
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=rip,
        regions=regions,
        stub_rva_ranges=((0x3000, 0x1000),),
    )
    kinds = {item["kind"] for item in observations}
    assert "rip_in_main_module_code" in kinds
    assert "left_stub_region" in kinds
    assert all(item.get("rip") == rip or item.get("oep_rva") == 0x1500 for item in observations)


def test_rip_inside_stub_does_not_emit_left_stub() -> None:
    regions = [
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ, protect_name="execute_read")
    ]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=MODULE_BASE + 0x3100,
        regions=regions,
        stub_rva_ranges=((0x3000, 0x1000),),
    )
    kinds = {item["kind"] for item in observations}
    assert "rip_in_main_module_code" in kinds
    assert "left_stub_region" not in kinds


def test_write_to_execute_and_ep_protect_change() -> None:
    previous = [
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_READWRITE, protect_name="readwrite")
    ]
    current = [
        _region(
            MODULE_BASE,
            MODULE_SIZE,
            _PAGE_EXECUTE_READ,
            protect_name="execute_read",
        )
    ]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous,
        entry_point_rva=0x1000,
    )
    kinds = {item["kind"] for item in observations}
    assert "write_to_execute" in kinds
    assert "ep_section_protect_changed" in kinds
    ep = next(item for item in observations if item["kind"] == "ep_section_protect_changed")
    assert ep["address"] == MODULE_BASE + 0x1000


def test_new_executable_region_when_base_appears() -> None:
    previous = [
        _region(MODULE_BASE, 0x1000, _PAGE_EXECUTE_READ, protect_name="execute_read")
    ]
    current = [
        _region(MODULE_BASE, 0x1000, _PAGE_EXECUTE_READ, protect_name="execute_read"),
        _region(
            MODULE_BASE + 0x1000,
            0x1000,
            _PAGE_EXECUTE_READWRITE,
            protect_name="execute_readwrite",
        ),
    ]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous,
    )
    kinds = [item["kind"] for item in observations]
    assert kinds.count("new_executable_region") == 1
    neo = next(item for item in observations if item["kind"] == "new_executable_region")
    assert neo["address"] == MODULE_BASE + 0x1000


def test_imports_resolved_only_with_hint() -> None:
    without = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=MODULE_BASE + 0x1200,
        regions=[
            _region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ, protect_name="execute_read")
        ],
        imports_resolved_hint=False,
    )
    assert all(item["kind"] != "imports_resolved" for item in without)

    with_hint = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=MODULE_BASE + 0x1200,
        regions=[
            _region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ, protect_name="execute_read")
        ],
        imports_resolved_hint=True,
    )
    assert any(item["kind"] == "imports_resolved" for item in with_hint)


def test_observations_feed_scorer_without_authoritative() -> None:
    previous = [
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_READWRITE, protect_name="readwrite")
    ]
    current = [
        _region(
            MODULE_BASE,
            MODULE_SIZE,
            _PAGE_EXECUTE_READ,
            protect_name="execute_read",
        )
    ]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        rip=MODULE_BASE + 0x1500,
        regions=current,
        previous_regions=previous,
        stub_rva_ranges=((0x3000, 0x1000),),
        entry_point_rva=0x1000,
        imports_resolved_hint=True,
    )
    assert len(observations) >= 3
    scored = score_oep_candidates(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        observations=observations,
        stub_rva_ranges=((0x3000, 0x1000),),
    )
    assert scored
    assert scored[0]["authoritative"] is False
    assert scored[0]["oep_rva"] == 0x1500 or scored[0]["score"] > 0


def test_collect_rejects_invalid_module_bounds() -> None:
    with pytest.raises(ValueError):
        collect_oep_observations(module_base=0, module_size=0x1000)
    with pytest.raises(ValueError):
        collect_oep_observations(module_base=MODULE_BASE, module_size=0)


@pytest.mark.parametrize(
    "bad_region",
    [7, "region", ["base", 0x1000], (0x1000, 0x100), None, 3.5, b"bytes"],
)
def test_region_accessors_tolerate_non_mapping(bad_region: object) -> None:
    # unpack.score_oep forwards previous_regions straight from client input on
    # the pydantic-free agent transport, so a non-Mapping element must read as an
    # unreadable region rather than crashing .get() with an AttributeError.
    assert region_base(bad_region) is None  # type: ignore[arg-type]
    assert region_size(bad_region) is None  # type: ignore[arg-type]
    assert region_protect(bad_region) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "regions",
    [
        [1, 2, 3],
        ["a", "b"],
        [[0x1000, 0x100]],
        [None],
        [(0x1000, 0x100)],
    ],
)
def test_index_and_find_skip_non_mapping_regions(regions: list[object]) -> None:
    assert index_regions_by_base(regions) == {}  # type: ignore[arg-type]
    assert find_region_at(regions, 0x1000) is None  # type: ignore[arg-type]


def test_index_regions_keeps_valid_and_drops_non_mapping() -> None:
    good = _region(MODULE_BASE, 0x1000, _PAGE_EXECUTE_READ, protect_name="execute_read")
    indexed = index_regions_by_base([good, 5, "x", None, [1, 2]])  # type: ignore[list-item]
    assert indexed == {MODULE_BASE: good}


@pytest.mark.parametrize(
    "previous_regions",
    [
        [1, 2, 3],
        ["a", "b"],
        [[0x1000, 0x100]],
        [None],
    ],
)
def test_collect_tolerates_non_mapping_previous_regions(
    previous_regions: list[object],
) -> None:
    # A malformed previous_regions must not crash the diff: with no valid prior
    # snapshot, a newly executable current region is still reported as new.
    current = [
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ, protect_name="execute_read")
    ]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous_regions,  # type: ignore[arg-type]
    )
    assert any(item["kind"] == "new_executable_region" for item in observations)


def test_collect_keeps_valid_previous_region_amid_non_mapping() -> None:
    # The one well-formed prior region still drives a write->execute observation
    # even when the client mixes in non-Mapping junk.
    previous = [
        7,
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_READWRITE, protect_name="readwrite"),
        "junk",
    ]
    current = [
        _region(MODULE_BASE, MODULE_SIZE, _PAGE_EXECUTE_READ, protect_name="execute_read")
    ]
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=MODULE_SIZE,
        regions=current,
        previous_regions=previous,  # type: ignore[list-item]
        entry_point_rva=0x1000,
    )
    kinds = {item["kind"] for item in observations}
    assert "write_to_execute" in kinds
