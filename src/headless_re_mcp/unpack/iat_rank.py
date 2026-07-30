"""Rank / filter IAT scan candidates and score import-table layouts.

Pure helpers used after native ``imports.scan`` / ``imports.read``. Never claims
universal unpack success; rebuild gates are fail-closed.
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

# Prefer classic PE image-low RVAs; deprioritize deep VMP-mapped regions.
_DEFAULT_HIGH_RVA_SOFT = 0x800000
_IME_MODULE_HINTS = frozenset({"imm32.dll", "msctf.dll"})
_IME_NAME_HINTS = frozenset(
    {
        "immgetcontext",
        "immreleasecontext",
        "immsetcompositionwindow",
        "winnlsenableime",
        "immisime",
    }
)


def analyze_import_entries(
    entries: list[JsonObject] | tuple[JsonObject, ...],
    *,
    pointer_size: int = 4,
) -> JsonObject:
    """Classify a read IAT window: contiguous vs half-sparse (API,null) vs junk."""
    if pointer_size not in {4, 8}:
        raise ValueError("pointer_size must be 4 or 8")
    total = len(entries)
    api = 0
    nulls = 0
    unresolved = 0
    modules: dict[str, int] = {}
    api_null_pairs = 0
    i = 0
    while i + 1 < total:
        a = entries[i]
        b = entries[i + 1]
        if (
            isinstance(a, dict)
            and isinstance(b, dict)
            and str(a.get("kind")) == "api"
            and str(b.get("kind")) == "null"
        ):
            api_null_pairs += 1
            i += 2
            continue
        i += 1
    for item in entries:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "")
        if kind == "api":
            api += 1
            mod = str(item.get("module") or "").casefold()
            if mod:
                modules[mod] = modules.get(mod, 0) + 1
        elif kind == "null":
            nulls += 1
        elif kind == "unresolved":
            unresolved += 1
    slots = max(total, 1)
    resolved_ratio = api / slots
    unresolved_ratio = unresolved / slots
    half_sparse = api_null_pairs >= 3 and api_null_pairs * 2 >= api
    layout = "empty"
    if total == 0:
        layout = "empty"
    elif half_sparse:
        layout = "half_sparse"
    elif resolved_ratio >= 0.6 and unresolved_ratio <= 0.25:
        layout = "dense"
    elif resolved_ratio >= 0.25:
        layout = "fragmented"
    else:
        layout = "junk"
    ime_only = _is_ime_dominated(modules, api)
    rebuild_allowed = layout in {"dense", "half_sparse"} and api >= 8 and not ime_only
    return {
        "slot_count": total,
        "api_count": api,
        "null_count": nulls,
        "unresolved_count": unresolved,
        "resolved_ratio": round(resolved_ratio, 4),
        "unresolved_ratio": round(unresolved_ratio, 4),
        "api_null_pairs": api_null_pairs,
        "layout": layout,
        "ime_dominated": ime_only,
        "modules": dict(sorted(modules.items(), key=lambda kv: (-kv[1], kv[0]))),
        "rebuild_allowed": rebuild_allowed,
        "rebuild_block_reason": _rebuild_block_reason(
            layout=layout,
            api=api,
            ime_only=ime_only,
            unresolved_ratio=unresolved_ratio,
        ),
        "claims_universal_unpack": False,
    }


def rank_iat_candidates(
    candidates: list[JsonObject] | tuple[JsonObject, ...],
    *,
    module_base: int | None = None,
    module_size: int | None = None,
    max_candidates: int = 8,
    high_rva_soft: int = _DEFAULT_HIGH_RVA_SOFT,
) -> JsonObject:
    """Deduplicate overlapping scan hits and score survivors for caller confirm."""
    scored: list[JsonObject] = []
    for raw in candidates:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        iat_va = item.get("iat_va")
        size = item.get("size")
        matched = int(item.get("matched_count") or 0)
        slots = int(item.get("slot_count") or matched or 1)
        kind = str(item.get("kind") or "unknown")
        conf = float(item.get("confidence") or 0.0)
        rva = item.get("iat_rva")
        if rva is None and isinstance(iat_va, int) and isinstance(module_base, int):
            rva = iat_va - module_base
            item["iat_rva"] = rva
        if not isinstance(iat_va, int) or not isinstance(size, int) or size <= 0:
            continue
        if (
            isinstance(module_base, int)
            and isinstance(module_size, int)
            and (iat_va < module_base or iat_va + size > module_base + module_size)
        ):
            continue
        density = matched / max(slots, 1)
        score = conf * 0.45 + min(1.0, matched / 32.0) * 0.35 + density * 0.2
        samples_value = item.get("sample_apis")
        samples: list[Any] = samples_value if isinstance(samples_value, list) else []
        ime_hits = _count_ime_samples(samples)
        sample_n = len(samples)
        if sample_n > 0 and (ime_hits >= 2 or ime_hits / sample_n >= 0.5):
            score *= 0.35
            item["noise_tags"] = list(item.get("noise_tags") or []) + ["ime_dominated"]
        if isinstance(rva, int) and rva >= high_rva_soft:
            score *= 0.55
            item["noise_tags"] = list(item.get("noise_tags") or []) + ["high_rva"]
        if kind == "call_site":
            score += 0.02
        item["rank_score"] = round(score, 4)
        item["density"] = round(density, 4)
        scored.append(item)

    scored.sort(
        key=lambda c: (
            -float(c.get("rank_score") or 0.0),
            -int(c.get("matched_count") or 0),
            int(c.get("iat_va") or 0),
        )
    )
    merged = _merge_overlaps(scored)
    if max_candidates > 0 and len(merged) > max_candidates:
        merged = merged[:max_candidates]
    best = merged[0] if merged else None
    return {
        "candidates": merged,
        "candidate_count": len(merged),
        "raw_candidate_count": len(scored),
        "best": best,
        "blind_selection": False,
        "claims_universal_unpack": False,
        "note": (
            "ranked/deduped heuristic candidates; caller must confirm via "
            "imports.read + rebuild gate"
        ),
    }


def gate_iat_rebuild(
    analysis: JsonObject,
    *,
    still_vm_stub_count: int | None = None,
    min_api: int = 8,
    max_stub_ratio: float = 0.35,
) -> JsonObject:
    """Fail-closed rebuild permission from layout analysis (+ optional stub stats)."""
    api = int(analysis.get("api_count") or 0)
    layout = str(analysis.get("layout") or "")
    ime = bool(analysis.get("ime_dominated"))
    allowed = bool(analysis.get("rebuild_allowed"))
    reasons: list[str] = []
    if analysis.get("rebuild_block_reason"):
        reasons.append(str(analysis["rebuild_block_reason"]))
    stub_count = still_vm_stub_count
    stub_ratio = None
    if stub_count is not None:
        denom = max(api + int(stub_count), 1)
        stub_ratio = float(stub_count) / float(denom)
        if stub_ratio > max_stub_ratio:
            allowed = False
            reasons.append(
                f"still_vm_stub_ratio={stub_ratio:.3f} exceeds max={max_stub_ratio}"
            )
    if api < min_api:
        allowed = False
        reasons.append(f"api_count={api} < min_api={min_api}")
    if ime:
        allowed = False
        reasons.append("ime_dominated_candidate")
    if layout in {"junk", "empty", "fragmented"}:
        # fragmented already clears rebuild_allowed usually; keep explicit.
        allowed = False
        if f"layout={layout}" not in reasons:
            reasons.append(f"layout={layout}")
    return {
        "rebuild_allowed": allowed,
        "reasons": reasons,
        "layout": layout,
        "api_count": api,
        "still_vm_stub_count": stub_count,
        "still_vm_stub_ratio": None if stub_ratio is None else round(stub_ratio, 4),
        "recoverability": (
            "iat_recoverable"
            if allowed
            else ("vm_coupled_dump_only" if (stub_count or 0) > api else "iat_insufficient")
        ),
        "claims_universal_unpack": False,
    }


def _rebuild_block_reason(
    *,
    layout: str,
    api: int,
    ime_only: bool,
    unresolved_ratio: float,
) -> str | None:
    if ime_only:
        return "ime_dominated_candidate"
    if layout == "junk":
        return "layout_junk"
    if layout == "empty":
        return "layout_empty"
    if layout == "fragmented":
        return "layout_fragmented"
    if api < 8:
        return f"api_count_below_8:{api}"
    if unresolved_ratio > 0.5 and layout != "half_sparse":
        return "unresolved_ratio_high"
    return None


def _is_ime_dominated(modules: dict[str, int], api: int) -> bool:
    if api <= 0:
        return False
    ime = 0
    for name, count in modules.items():
        if name in _IME_MODULE_HINTS or name.endswith("ime"):
            ime += count
    return ime >= max(3, int(api * 0.7))


def _count_ime_samples(samples: list[Any]) -> int:
    hits = 0
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        mod = str(sample.get("module") or "").casefold()
        name = str(sample.get("name") or "").casefold()
        if mod in _IME_MODULE_HINTS or name in _IME_NAME_HINTS:
            hits += 1
    return hits


def _merge_overlaps(candidates: list[JsonObject]) -> list[JsonObject]:
    """Keep highest-scoring candidate per overlapping VA range; union kinds."""
    kept: list[JsonObject] = []
    for item in candidates:
        va = int(item["iat_va"])
        size = int(item["size"])
        end = va + size
        merged_into = False
        for existing in kept:
            eva = int(existing["iat_va"])
            eend = eva + int(existing["size"])
            if not (end <= eva or eend <= va):
                # Overlap: keep better score; union kinds/tags/samples.
                kinds = {
                    str(existing.get("kind") or ""),
                    str(item.get("kind") or ""),
                }
                winner = (
                    item
                    if float(item.get("rank_score") or 0)
                    > float(existing.get("rank_score") or 0)
                    else existing
                )
                loser = existing if winner is item else item
                merged = dict(winner)
                merged["alt_kinds"] = sorted(k for k in kinds if k)
                tags = list(winner.get("noise_tags") or [])
                tags.extend(loser.get("noise_tags") or [])
                merged["noise_tags"] = sorted(set(tags))
                samples: list[Any] = []
                for src in (winner, loser):
                    raw = src.get("sample_apis")
                    if isinstance(raw, list):
                        samples.extend(x for x in raw if isinstance(x, dict))
                if samples:
                    merged["sample_apis"] = samples[:16]
                    if "ime_dominated" not in merged["noise_tags"]:
                        ime_hits = _count_ime_samples(samples)
                        if ime_hits >= 2 or ime_hits / max(len(samples), 1) >= 0.5:
                            merged["noise_tags"] = sorted(
                                set(merged["noise_tags"] + ["ime_dominated"])
                            )
                            merged["rank_score"] = round(
                                float(merged.get("rank_score") or 0) * 0.35, 4
                            )
                existing.clear()
                existing.update(merged)
                merged_into = True
                break
        if not merged_into:
            kept.append(dict(item))
    kept.sort(
        key=lambda c: (
            -float(c.get("rank_score") or 0.0),
            -int(c.get("matched_count") or 0),
            int(c.get("iat_va") or 0),
        )
    )
    return kept
