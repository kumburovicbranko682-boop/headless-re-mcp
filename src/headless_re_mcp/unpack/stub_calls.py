"""Count E8 stub calls vs FF15/FF25 API-ish indirect calls in a dump.

Used as a fail-closed signal for IAT rebuild: many E8 targets still landing in
VMP-like sections means the dump remains VM-coupled even if some IAT slots resolve.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from headless_re_mcp.unpack.pe_rebuild import PeRebuildError, parse_runtime_headers

JsonObject = dict[str, Any]

_KNOWN_CODE_NAMES = frozenset(
    {
        ".text",
        "code",
        ".code",
        "text",
        ".textbss",
        ".init",
        ".plt",
        ".text$mn",
        # Delphi / Borland
        "CODE",
    }
)
_KNOWN_DATA_NAMES = frozenset(
    {
        ".data",
        ".rdata",
        ".rsrc",
        ".reloc",
        ".idata",
        ".edata",
        ".tls",
        ".bss",
        ".pdata",
        ".xdata",
        ".didat",
        ".gfids",
        ".00cfg",
        ".CRT",
        # Delphi / Borland
        "DATA",
        "BSS",
        ".itext",
    }
)
_VMP_NAME = re.compile(
    r"(vmp|themida|\.fk|\.\'|\.boot|\.vmp\d*)",
    re.IGNORECASE,
)
_IMAGE_SCN_MEM_EXECUTE = 0x20000000


def vmp_like_section_ranges(
    sections: Sequence[JsonObject] | tuple[JsonObject, ...],
) -> list[tuple[int, int, str]]:
    """Heuristic VMP/protector section RVA ranges from PE section metadata."""
    out: list[tuple[int, int, str]] = []
    known_fold = {n.casefold() for n in _KNOWN_CODE_NAMES | _KNOWN_DATA_NAMES}
    for section in sections:
        if not isinstance(section, dict):
            continue
        name = str(section.get("name") or "").rstrip("\0")
        rva = section.get("virtual_address")
        size = section.get("virtual_size") or section.get("raw_size") or 0
        chars = int(section.get("characteristics") or 0)
        if type(rva) is not int or rva < 0:
            continue
        if type(size) is not int or size <= 0:
            continue
        name_key = name.casefold()
        known = name_key in known_fold
        vmp_named = bool(_VMP_NAME.search(name))
        executable = bool(chars & _IMAGE_SCN_MEM_EXECUTE)
        weird = (not known) and (executable or vmp_named or (0 < len(name) <= 4))
        if vmp_named or (weird and not known):
            if known and not vmp_named:
                continue
            out.append((rva, size, name))
    return out


def code_section_ranges(
    sections: Sequence[JsonObject] | tuple[JsonObject, ...],
) -> list[tuple[int, int, str]]:
    """Pick primary application code sections (exclude VMP-like)."""
    vmp = {(r, s) for r, s, _ in vmp_like_section_ranges(sections)}
    known_code = {n.casefold() for n in _KNOWN_CODE_NAMES}
    known_data = {n.casefold() for n in _KNOWN_DATA_NAMES}
    out: list[tuple[int, int, str]] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        name = str(section.get("name") or "").rstrip("\0")
        rva = section.get("virtual_address")
        size = section.get("virtual_size") or section.get("raw_size") or 0
        chars = int(section.get("characteristics") or 0)
        if type(rva) is not int or type(size) is not int or size <= 0:
            continue
        if (rva, size) in vmp:
            continue
        name_key = name.casefold()
        executable = bool(chars & _IMAGE_SCN_MEM_EXECUTE)
        if name_key in known_code or (
            executable and name_key not in known_data
        ):
            if any(rva < vr + vs and vr < rva + size for vr, vs in vmp):
                continue
            out.append((rva, size, name))
    return out


def count_stub_vs_api_calls(
    image: bytes,
    *,
    image_base: int,
    code_ranges: Sequence[tuple[int, int]] | Sequence[tuple[int, int, str]],
    stub_ranges: Sequence[tuple[int, int]] | Sequence[tuple[int, int, str]],
    iat_va: int | None = None,
    iat_size: int | None = None,
    is_64bit: bool = False,
    max_scan_bytes: int = 8 * 1024 * 1024,
) -> JsonObject:
    """Scan code bytes for E8 (rel32) vs FF15/FF25 indirect calls."""
    stub_norm = [(int(r[0]), int(r[1])) for r in stub_ranges]
    code_norm = [(int(r[0]), int(r[1])) for r in code_ranges]
    e8_total = 0
    e8_to_stub = 0
    e8_to_code = 0
    e8_other = 0
    ff15 = 0
    ff25 = 0
    ff_to_iat = 0
    scanned = 0
    iat_lo = iat_va if isinstance(iat_va, int) else None
    iat_hi = (
        (iat_va + iat_size)
        if isinstance(iat_va, int) and isinstance(iat_size, int) and iat_size > 0
        else None
    )

    def _in_ranges(rva: int, ranges: list[tuple[int, int]]) -> bool:
        return any(start <= rva < start + size for start, size in ranges)

    for rva0, size0 in code_norm:
        if size0 <= 0:
            continue
        take = min(size0, max_scan_bytes - scanned)
        if take <= 0:
            break
        if rva0 + take > len(image):
            take = max(0, len(image) - rva0)
        blob = image[rva0 : rva0 + take]
        scanned += len(blob)
        i = 0
        n = len(blob)
        while i + 5 <= n:
            b0 = blob[i]
            if b0 == 0xE8 and i + 5 <= n:
                rel = int.from_bytes(blob[i + 1 : i + 5], "little", signed=True)
                next_va = image_base + rva0 + i + 5
                target_va = next_va + rel
                target_rva = target_va - image_base
                e8_total += 1
                if _in_ranges(target_rva, stub_norm):
                    e8_to_stub += 1
                elif _in_ranges(target_rva, code_norm):
                    e8_to_code += 1
                else:
                    e8_other += 1
                i += 5
                continue
            if b0 == 0xFF and i + 6 <= n and blob[i + 1] in (0x15, 0x25):
                if is_64bit:
                    rel = int.from_bytes(blob[i + 2 : i + 6], "little", signed=True)
                    slot_va = image_base + rva0 + i + 6 + rel
                else:
                    slot_va = int.from_bytes(blob[i + 2 : i + 6], "little", signed=False)
                if blob[i + 1] == 0x15:
                    ff15 += 1
                else:
                    ff25 += 1
                if iat_lo is not None and iat_hi is not None and iat_lo <= slot_va < iat_hi:
                    ff_to_iat += 1
                i += 6
                continue
            i += 1

    api_ish = ff15 + ff25
    still_vm_stub_count = e8_to_stub
    return {
        "scanned_bytes": scanned,
        "e8_total": e8_total,
        "e8_to_stub": e8_to_stub,
        "e8_to_code": e8_to_code,
        "e8_other": e8_other,
        "ff15_count": ff15,
        "ff25_count": ff25,
        "ff_indirect_count": api_ish,
        "ff_to_iat_count": ff_to_iat,
        "still_vm_stub_count": still_vm_stub_count,
        "api_call_site_count": api_ish,
        "stub_vs_api_ratio": round(
            float(still_vm_stub_count) / float(max(still_vm_stub_count + api_ish, 1)),
            4,
        ),
        "claims_universal_unpack": False,
    }


def analyze_dump_stub_coupling(
    dump_path: str | Path,
    *,
    iat_va: int | None = None,
    iat_size: int | None = None,
    image_base: int | None = None,
    max_scan_bytes: int = 8 * 1024 * 1024,
) -> JsonObject:
    """Parse a runtime dump and count stub-coupled E8 calls vs API-ish FF15/25."""
    path = Path(dump_path)
    data = path.read_bytes()
    try:
        headers = parse_runtime_headers(data)
    except PeRebuildError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "still_vm_stub_count": None,
            "claims_universal_unpack": False,
        }
    sections_value = headers.get("sections")
    sections: list[JsonObject] = (
        [item for item in sections_value if isinstance(item, dict)]
        if isinstance(sections_value, list)
        else []
    )
    base = image_base if isinstance(image_base, int) else int(headers.get("image_base") or 0)
    is_64bit = str(headers.get("architecture") or "").lower() in {"x64", "amd64", "x86_64"}
    stub = vmp_like_section_ranges(sections)
    code = code_section_ranges(sections)
    if not code:
        best: tuple[int, int, str] | None = None
        for section in sections:
            if not isinstance(section, dict):
                continue
            chars = int(section.get("characteristics") or 0)
            if not (chars & _IMAGE_SCN_MEM_EXECUTE):
                continue
            rva = section.get("virtual_address")
            size = section.get("virtual_size") or 0
            name = str(section.get("name") or "")
            if type(rva) is not int or type(size) is not int or size <= 0:
                continue
            if any(rva == sr and size == ss for sr, ss, _ in stub):
                continue
            if best is None or size > best[1]:
                best = (rva, size, name)
        if best is not None:
            code = [best]
    counts = count_stub_vs_api_calls(
        data,
        image_base=base,
        code_ranges=code,
        stub_ranges=stub,
        iat_va=iat_va,
        iat_size=iat_size,
        is_64bit=is_64bit,
        max_scan_bytes=max_scan_bytes,
    )
    code_nonzero = 0
    code_total = 0
    for rva, size, _name in code:
        take = min(size, max(0, len(data) - rva))
        if take <= 0:
            continue
        blob = data[rva : rva + take]
        code_total += len(blob)
        code_nonzero += sum(1 for b in blob if b)
    code_nonzero_ratio = round(code_nonzero / float(max(code_total, 1)), 4)
    return {
        "ok": True,
        "dump_path": str(path),
        "image_base": base,
        "architecture": headers.get("architecture"),
        "stub_sections": [{"rva": r, "size": s, "name": n} for r, s, n in stub],
        "code_sections": [{"rva": r, "size": s, "name": n} for r, s, n in code],
        "code_nonzero_ratio": code_nonzero_ratio,
        "code_bytes": code_total,
        **counts,
    }
