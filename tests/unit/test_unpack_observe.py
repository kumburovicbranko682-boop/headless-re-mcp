"""Unit tests for unpack OEP observation collectors (no live debugger)."""

from __future__ import annotations

import pytest

from headless_re_mcp.unpack.observe import (
    collect_oep_observations,
    is_executable_protect,
    is_writable_protect,
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


def test_real_executable_upx0_is_not_a_stub_range() -> None:
    """UPX0 stays out of the stub ranges even when it carries MEM_EXECUTE.

    UPX0 is the region the stub decompresses the original code into -- the OEP
    lands there -- while the stub itself lives in UPX1. The check above only
    passed because its fixture omitted ``characteristics``, leaving UPX0
    non-executable. A real UPX0 is RWX (``0xE0000000``, MEM_EXECUTE set) and a
    4-char non-dotted unknown name, so the generic short-executable heuristic
    used to catch it and mark the OEP's own region as stub. That suppressed the
    ``left_stub_region`` signal (rip in UPX0 read as "still in the stub") and
    penalised the true OEP candidate for the most common packer.
    """
    mem_execute = 0x20000000
    read_write = 0xC0000000
    sections = [
        {
            "name": "UPX0",
            "virtual_address": 0x1000,
            "virtual_size": 0x2000,
            "characteristics": read_write | mem_execute,
        },
        {
            "name": "UPX1",
            "virtual_address": 0x3000,
            "virtual_size": 0x1000,
            "characteristics": read_write | mem_execute,
        },
        {
            "name": ".rsrc",
            "virtual_address": 0x4000,
            "virtual_size": 0x500,
            "characteristics": 0x40000040,
        },
    ]
    ranges = stub_rva_ranges_from_sections(sections)
    assert ranges == [(0x3000, 0x1000)]

    # rip at the unpacked OEP inside UPX0 must read as having left the stub.
    observations = collect_oep_observations(
        module_base=MODULE_BASE,
        module_size=0x5000,
        rip=MODULE_BASE + 0x1500,
        regions=[],
        stub_rva_ranges=ranges,
    )
    assert "left_stub_region" in {item["kind"] for item in observations}

    # The exclusion is narrow: a genuine short executable protector section with
    # an unknown name is still classified as a stub range.
    protector = [
        {
            "name": "GsF",
            "virtual_address": 0x2000,
            "virtual_size": 0x400,
            "characteristics": 0x60000020,
        }
    ]
    assert stub_rva_ranges_from_sections(protector) == [(0x2000, 0x400)]


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
