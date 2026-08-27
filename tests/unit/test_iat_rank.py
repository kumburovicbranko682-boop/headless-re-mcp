from __future__ import annotations

import pytest

from headless_re_mcp.unpack.iat_rank import (
    analyze_import_entries,
    gate_iat_rebuild,
    rank_iat_candidates,
)


def test_half_sparse_layout_and_gate() -> None:
    entries = []
    for _ in range(10):
        entries.append({"kind": "api", "module": "kernel32.dll", "name": "CreateFileA"})
        entries.append({"kind": "null"})
    analysis = analyze_import_entries(entries)
    assert analysis["layout"] == "half_sparse"
    assert analysis["api_null_pairs"] == 10
    assert analysis["rebuild_allowed"] is True
    gate = gate_iat_rebuild(analysis)
    assert gate["rebuild_allowed"] is True
    assert gate["recoverability"] == "iat_recoverable"


def test_ime_dominated_blocks_rebuild() -> None:
    entries = [
        {"kind": "api", "module": "imm32.dll", "name": "ImmGetContext"} for _ in range(11)
    ]
    analysis = analyze_import_entries(entries)
    assert analysis["ime_dominated"] is True
    assert analysis["rebuild_allowed"] is False
    gate = gate_iat_rebuild(analysis)
    assert gate["rebuild_allowed"] is False


def test_junk_layout_with_high_unresolved() -> None:
    entries = [{"kind": "unresolved", "value": i} for i in range(20)]
    entries[0] = {"kind": "api", "module": "kernel32.dll", "name": "HeapFree"}
    analysis = analyze_import_entries(entries)
    assert analysis["layout"] == "junk"
    assert analysis["rebuild_allowed"] is False


def test_rank_dedupes_overlap_and_penalizes_high_rva_ime() -> None:
    ranked = rank_iat_candidates(
        [
            {
                "iat_va": 0x431678,
                "iat_rva": 0x31678,
                "size": 44,
                "matched_count": 11,
                "slot_count": 11,
                "kind": "consecutive",
                "confidence": 1.0,
                "sample_apis": [
                    {"module": "imm32.dll", "name": "ImmGetContext"},
                    {"module": "imm32.dll", "name": "ImmReleaseContext"},
                ],
            },
            {
                "iat_va": 0x431678,
                "iat_rva": 0x31678,
                "size": 44,
                "matched_count": 11,
                "slot_count": 11,
                "kind": "sparse",
                "confidence": 1.0,
                "sample_apis": [
                    {"module": "imm32.dll", "name": "ImmGetContext"},
                ],
            },
            {
                "iat_va": 0xF82000,
                "iat_rva": 0xB82000,
                "size": 120,
                "matched_count": 17,
                "slot_count": 30,
                "kind": "sparse",
                "confidence": 0.66,
                "sample_apis": [
                    {"module": "kernel32.dll", "name": "LoadLibraryA"},
                    {"module": "user32.dll", "name": "GetKeyboardType"},
                ],
            },
            {
                "iat_va": 0x45C0F0,
                "iat_rva": 0x5C0F0,
                "size": 148,
                "matched_count": 6,
                "slot_count": 37,
                "kind": "call_site",
                "confidence": 0.2,
                "sample_apis": [
                    {"module": "kernel32.dll", "name": "TlsGetValue"},
                ],
            },
        ],
        module_base=0x400000,
        module_size=0x2000000,
        max_candidates=8,
    )
    assert ranked["candidate_count"] == 3
    assert ranked["raw_candidate_count"] == 4
    # Overlapping 0x431678 collapsed; alt_kinds present.
    ime = next(c for c in ranked["candidates"] if c["iat_va"] == 0x431678)
    assert "alt_kinds" in ime
    assert "ime_dominated" in (ime.get("noise_tags") or [])


@pytest.mark.parametrize(
    ("analysis", "reason_fragment"),
    [
        ({"layout": "fragmented", "api_count": 20}, "layout=fragmented"),
        ({"layout": "empty", "api_count": 20}, "layout=empty"),
        ({"layout": "junk", "api_count": 20}, "layout=junk"),
        ({"layout": "dense", "api_count": 3}, "api_count=3"),
        ({"layout": "half_sparse", "api_count": 20, "ime_dominated": True}, "ime_dominated"),
    ],
)
def test_gate_is_fail_closed_against_a_rebuild_allowed_analysis(
    analysis: dict[str, object], reason_fragment: str
) -> None:
    """The gate re-derives permission; it never trusts an analysis dict's own flag.

    ``analyze_import_entries`` clears ``rebuild_allowed`` for these shapes, but the
    gate takes an ``analysis`` dict that a direct or stale caller can hand over
    with the flag still set to True. A rebuild attempted on junk, an empty or
    fragmented table, an IME-only stub, or too few imports corrupts the dump it
    claims to repair, so the gate must recompute the block from the layout and
    counts rather than pass the optimistic flag through.
    """
    poisoned = {"rebuild_allowed": True, "ime_dominated": False, **analysis}

    gate = gate_iat_rebuild(poisoned)

    assert gate["rebuild_allowed"] is False
    assert any(reason_fragment in reason for reason in gate["reasons"])


def test_stub_ratio_forces_vm_coupled() -> None:
    entries = [
        {"kind": "api", "module": "kernel32.dll", "name": f"Api{i}"} for i in range(10)
    ]
    analysis = analyze_import_entries(entries)
    gate = gate_iat_rebuild(analysis, still_vm_stub_count=40)
    assert gate["rebuild_allowed"] is False
    assert gate["recoverability"] == "vm_coupled_dump_only"