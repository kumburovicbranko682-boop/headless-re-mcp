"""Build OEP observation dicts from runtime memory/register snapshots.

Pure functions only — callers supply snapshots from the debugger (or fixtures).
Nothing here invents RPC or treats a single heuristic as confirmed OEP.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

JsonObject = dict[str, Any]
RegionLike = Mapping[str, Any]

# Windows PAGE_* base flags (low byte).
_PAGE_READONLY = 0x02
_PAGE_READWRITE = 0x04
_PAGE_WRITECOPY = 0x08
_PAGE_EXECUTE = 0x10
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_EXECUTE_WRITECOPY = 0x80

_EXECUTABLE_BASE = frozenset(
    {
        _PAGE_EXECUTE,
        _PAGE_EXECUTE_READ,
        _PAGE_EXECUTE_READWRITE,
        _PAGE_EXECUTE_WRITECOPY,
    }
)
_WRITABLE_BASE = frozenset(
    {
        _PAGE_READWRITE,
        _PAGE_WRITECOPY,
        _PAGE_EXECUTE_READWRITE,
        _PAGE_EXECUTE_WRITECOPY,
    }
)

_STUB_SECTION_NAME = re.compile(
    r"^(upx[1-9]\w*|\.upx|aspack|themida|vmp\d*|.*stub.*)$",
    re.IGNORECASE,
)
# VMProtect-like / weird protector section names (e.g. .fkF / .'FL).
_VMP_LIKE_SECTION = re.compile(
    r"(vmp|themida|\.fk|\.\'|\.boot)",
    re.IGNORECASE,
)
_KNOWN_APP_SECTIONS = frozenset(
    {
        ".text",
        "code",
        ".code",
        "text",
        ".data",
        "data",
        ".rdata",
        ".rsrc",
        ".reloc",
        ".idata",
        ".edata",
        ".tls",
        ".bss",
        "bss",
        ".pdata",
        ".xdata",
    }
)
_IMAGE_SCN_MEM_EXECUTE = 0x20000000


def protect_base(protect: int) -> int:
    """Return the PAGE_* base flag (low 8 bits) from a Protect value."""
    return int(protect) & 0xFF


def is_executable_protect(protect: int) -> bool:
    return protect_base(protect) in _EXECUTABLE_BASE


def is_writable_protect(protect: int) -> bool:
    return protect_base(protect) in _WRITABLE_BASE


def region_base(region: RegionLike) -> int | None:
    value = region.get("base")
    if type(value) is int and value >= 0:
        return value
    return None


def region_size(region: RegionLike) -> int | None:
    value = region.get("size")
    if type(value) is int and value > 0:
        return value
    return None


def region_protect(region: RegionLike) -> int | None:
    value = region.get("protect")
    if type(value) is int and value >= 0:
        return value
    name = str(region.get("protect_name") or "").lower()
    if not name or name == "none":
        return None
    if "execute" in name and "write" in name:
        return _PAGE_EXECUTE_READWRITE
    if "execute" in name and "read" in name:
        return _PAGE_EXECUTE_READ
    if "execute" in name:
        return _PAGE_EXECUTE
    if "write" in name:
        return _PAGE_READWRITE
    if "read" in name:
        return _PAGE_READONLY
    return None


def region_covers(region: RegionLike, address: int) -> bool:
    base = region_base(region)
    size = region_size(region)
    if base is None or size is None:
        return False
    return base <= address < base + size


def find_region_at(
    regions: Sequence[RegionLike],
    address: int,
) -> RegionLike | None:
    for region in regions:
        if region_covers(region, address):
            return region
    return None


def index_regions_by_base(
    regions: Sequence[RegionLike],
) -> dict[int, RegionLike]:
    indexed: dict[int, RegionLike] = {}
    for region in regions:
        base = region_base(region)
        if base is not None:
            indexed[base] = region
    return indexed


def overlaps_module(region: RegionLike, module_base: int, module_size: int) -> bool:
    base = region_base(region)
    size = region_size(region)
    if base is None or size is None or module_size <= 0:
        return False
    module_end = module_base + module_size
    return base < module_end and (base + size) > module_base


def clip_address_to_module(address: int, module_base: int, module_size: int) -> int | None:
    if module_size <= 0:
        return None
    if module_base <= address < module_base + module_size:
        return address
    return None


def stub_rva_ranges_from_sections(
    sections: Sequence[RegionLike],
) -> list[tuple[int, int]]:
    """Derive stub RVA ranges from PE section names (UPX1-like, VMP-like, etc.)."""
    ranges: list[tuple[int, int]] = []
    known = {n.casefold() for n in _KNOWN_APP_SECTIONS}
    for section in sections:
        name = str(section.get("name") or "").rstrip("\0")
        rva = section.get("virtual_address")
        size = section.get("virtual_size") or section.get("raw_size")
        if type(rva) is not int or rva < 0:
            continue
        if type(size) is not int or size <= 0:
            continue
        name_key = name.casefold()
        chars = int(section.get("characteristics") or 0)
        executable = bool(chars & _IMAGE_SCN_MEM_EXECUTE)
        named_stub = bool(_STUB_SECTION_NAME.match(name) or _VMP_LIKE_SECTION.search(name))
        weird_exec = (
            name_key not in known
            and executable
            and 0 < len(name) <= 4
            and not name_key.startswith(".")
        ) or (name_key not in known and named_stub)
        # Also treat unknown short dotted names like .fkF / .'FL as stubs.
        weird_dot = (
            name.startswith(".")
            and name_key not in known
            and (executable or named_stub or len(name) <= 4)
        )
        if named_stub or weird_exec or weird_dot:
            ranges.append((rva, size))
    return ranges


def _in_stub_ranges(
    rva: int,
    ranges: Sequence[tuple[int, int]],
) -> bool:
    return any(start <= rva < start + size for start, size in ranges)


def collect_oep_observations(
    *,
    module_base: int,
    module_size: int,
    rip: int | None = None,
    regions: Sequence[RegionLike] = (),
    previous_regions: Sequence[RegionLike] | None = None,
    stub_rva_ranges: Sequence[tuple[int, int]] = (),
    entry_point_rva: int | None = None,
    imports_resolved_hint: bool = False,
) -> list[JsonObject]:
    """Diff runtime snapshots into observation dicts consumed by ``score_oep_candidates``.

    ``imports_resolved`` is emitted only when ``imports_resolved_hint`` is true.
    """
    if type(module_base) is not int or module_base <= 0:
        raise ValueError("module_base must be a positive integer")
    if type(module_size) is not int or module_size <= 0:
        raise ValueError("module_size must be a positive integer")

    observations: list[JsonObject] = []
    module_end = module_base + module_size
    ep_va = (
        module_base + entry_point_rva
        if type(entry_point_rva) is int and entry_point_rva >= 0
        else None
    )

    if previous_regions is not None:
        prev_by_base = index_regions_by_base(previous_regions)
        curr_by_base = index_regions_by_base(regions)
        for base, curr in curr_by_base.items():
            if not overlaps_module(curr, module_base, module_size):
                continue
            curr_protect = region_protect(curr)
            if curr_protect is None:
                continue
            prev = prev_by_base.get(base)
            anchor = clip_address_to_module(
                max(base, module_base),
                module_base,
                module_size,
            )
            if anchor is None:
                continue

            if prev is None:
                if is_executable_protect(curr_protect):
                    observations.append(
                        {
                            "kind": "new_executable_region",
                            "address": anchor,
                            "region_base": base,
                            "protect": curr_protect,
                            "protect_name": curr.get("protect_name"),
                        }
                    )
                continue

            prev_protect = region_protect(prev)
            if prev_protect is None or prev_protect == curr_protect:
                continue

            if ep_va is not None and (
                region_covers(curr, ep_va) or region_covers(prev, ep_va)
            ):
                observations.append(
                    {
                        "kind": "ep_section_protect_changed",
                        "address": ep_va,
                        "region_base": base,
                        "previous_protect": prev_protect,
                        "protect": curr_protect,
                        "protect_name": curr.get("protect_name"),
                    }
                )

            prev_exec = is_executable_protect(prev_protect)
            curr_exec = is_executable_protect(curr_protect)
            if (
                is_writable_protect(prev_protect)
                and not prev_exec
                and curr_exec
            ):
                observations.append(
                    {
                        "kind": "write_to_execute",
                        "address": anchor,
                        "region_base": base,
                        "previous_protect": prev_protect,
                        "protect": curr_protect,
                        "protect_name": curr.get("protect_name"),
                    }
                )
            elif not prev_exec and curr_exec:
                observations.append(
                    {
                        "kind": "new_executable_region",
                        "address": anchor,
                        "region_base": base,
                        "previous_protect": prev_protect,
                        "protect": curr_protect,
                        "protect_name": curr.get("protect_name"),
                    }
                )

    if type(rip) is int and module_base <= rip < module_end:
        covering = find_region_at(regions, rip)
        covering_protect = region_protect(covering) if covering is not None else None
        if covering_protect is not None and is_executable_protect(covering_protect):
            observations.append(
                {
                    "kind": "rip_in_main_module_code",
                    "rip": rip,
                    "protect": covering_protect,
                    "protect_name": covering.get("protect_name") if covering else None,
                }
            )
        elif covering is None and not regions:
            # No region map: still allow RIP-in-module as a weak signal source.
            observations.append({"kind": "rip_in_main_module_code", "rip": rip})

        if stub_rva_ranges and not _in_stub_ranges(rip - module_base, stub_rva_ranges):
            observations.append(
                {
                    "kind": "left_stub_region",
                    "rip": rip,
                    "oep_rva": rip - module_base,
                }
            )

    if imports_resolved_hint:
        hint_address: int | None = None
        if type(rip) is int and module_base <= rip < module_end:
            hint_address = rip
        elif ep_va is not None and module_base <= ep_va < module_end:
            hint_address = ep_va
        if hint_address is not None:
            observations.append(
                {
                    "kind": "imports_resolved",
                    "address": hint_address,
                    "hint": True,
                }
            )

    return observations
