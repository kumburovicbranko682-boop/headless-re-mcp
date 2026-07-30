"""Pause-point quality gate: UI-visible != IAT-ready.

Used after a runtime pause / dump to decide whether IAT rebuild is worth attempting.
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]


def assess_pause_quality(
    *,
    ui_visible: bool | None = None,
    layout: str | None = None,
    rebuild_allowed: bool | None = None,
    recoverability: str | None = None,
    still_vm_stub_count: int | None = None,
    api_call_site_count: int | None = None,
    resolved_ratio: float | None = None,
    oep_role: str | None = None,
    code_nonzero_ratio: float | None = None,
    min_code_nonzero_ratio: float = 0.05,
) -> JsonObject:
    """Classify pause quality for IAT work. Never claims unpack success."""
    reasons: list[str] = []
    iat_ready = True
    code_not_ready = (
        isinstance(code_nonzero_ratio, float)
        and code_nonzero_ratio < min_code_nonzero_ratio
    )
    if ui_visible is True:
        reasons.append("ui_visible_only_not_sufficient")
    if code_not_ready:
        iat_ready = False
        assert code_nonzero_ratio is not None
        reasons.append(f"code_not_decrypted:nonzero_ratio={code_nonzero_ratio:.4f}")
    if layout in {"junk", "empty", "fragmented"}:
        iat_ready = False
        reasons.append(f"layout={layout}")
    if rebuild_allowed is False:
        iat_ready = False
        reasons.append("rebuild_not_allowed")
    if recoverability == "vm_coupled_dump_only":
        iat_ready = False
        reasons.append("vm_coupled_dump_only")
    elif recoverability == "iat_insufficient":
        iat_ready = False
        reasons.append("iat_insufficient")
    if (
        isinstance(still_vm_stub_count, int)
        and isinstance(api_call_site_count, int)
        and still_vm_stub_count > max(api_call_site_count, 1) * 2
    ):
        iat_ready = False
        reasons.append("stub_calls_dominate_api_sites")
    if isinstance(resolved_ratio, float) and resolved_ratio < 0.25:
        iat_ready = False
        reasons.append("resolved_ratio_low")
    if oep_role in {"packed_ep"}:
        reasons.append("oep_still_packed_ep")
    if (
        rebuild_allowed is True
        and recoverability == "iat_recoverable"
        and not code_not_ready
    ):
        iat_ready = True
        reasons = [r for r in reasons if r != "ui_visible_only_not_sufficient"]
        if ui_visible is True:
            reasons.append("ui_visible_and_iat_gate_ok")
    quality = "iat_ready" if iat_ready else "observe_only"
    if code_not_ready:
        quality = "code_not_ready"
    elif recoverability == "vm_coupled_dump_only":
        quality = "vm_coupled_dump_only"
    elif not iat_ready and ui_visible:
        quality = "ui_visible_not_iat_ready"
    return {
        "quality": quality,
        "iat_ready": iat_ready,
        "ui_visible": ui_visible,
        "code_nonzero_ratio": code_nonzero_ratio,
        "reasons": reasons,
        "recoverability": recoverability,
        "claims_universal_unpack": False,
        "note": "UI window visible does not imply IAT is rebuilt or process is unpack-complete",
    }
