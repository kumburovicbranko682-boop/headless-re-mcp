"""Non-authoritative unpack routing from detection candidates."""

from __future__ import annotations

import re
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from headless_re_mcp.backends.x64dbg.stealth import profile_from_candidates

JsonObject = dict[str, Any]
_STEALTH_FIRST_TOOLS: Final[tuple[str, ...]] = (
    "dynamic.stealth.set",
    "dynamic.launch",
)

_UPX_NAME = re.compile(r"\bupx\b", re.IGNORECASE)
_DOTNET_NAME = re.compile(r"(\.net|dotnet|dnlib|reactor|confuser)", re.IGNORECASE)
_VM_NAME = re.compile(r"(vmprotect|themida|vmp\b)", re.IGNORECASE)
_VMP_SECTION = re.compile(r"(^|\.)vmp|vmprotect", re.IGNORECASE)

_PACKER_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"packer", "protector", "obfuscator"}
)
_ALLOWED_FORCE_ROUTES: Final[frozenset[str]] = frozenset(
    {"upx", "dotnet", "bounded_dynamic", "generic_dynamic", "none"}
)


class UnpackRecommendation(BaseModel):
    """Bounded routing advice; never claims unpack success by itself."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    route: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    suggested_tools: tuple[str, ...] = ()
    candidates: tuple[JsonObject, ...] = ()
    authoritative: bool = False
    # For bounded_dynamic: expected recoverability posture before runtime gates.
    recoverability_hint: str | None = None
    stealth_profile: str | None = None

    def to_dict(self) -> JsonObject:
        value = self.model_dump(mode="json")
        if not isinstance(value, dict):
            raise TypeError("unpack recommendation did not serialize to an object")
        return value


def pe_suggests_vm_protector(
    *,
    finding_ids: list[str] | tuple[str, ...] = (),
    section_names: list[str] | tuple[str, ...] = (),
) -> bool:
    """Heuristic PE anomalies that often accompany VMProtect-like stubs (non-authoritative)."""
    ids = " | ".join(str(item) for item in finding_ids)
    if any(_VMP_SECTION.search(str(name)) for name in section_names):
        return True
    has_high_entropy = "high-entropy:" in ids
    has_sparse_imports = "sparse-imports" in ids
    has_gap = "virtual-raw-gap:" in ids
    has_bad_ep = "entry-point-not-executable" in ids
    has_rwx = "rwx-section:" in ids
    return bool(
        has_high_entropy
        and has_sparse_imports
        and (has_gap or has_bad_ep or has_rwx)
    )


def _attach_stealth(result: UnpackRecommendation) -> UnpackRecommendation:
    profile = profile_from_candidates(result.candidates)
    tools = result.suggested_tools
    if profile:
        extra = tuple(name for name in _STEALTH_FIRST_TOOLS if name not in tools)
        tools = extra + tools
    return result.model_copy(update={"stealth_profile": profile, "suggested_tools": tools})


def recommend_unpack_route(
    candidates: list[JsonObject] | tuple[JsonObject, ...],
    *,
    pe_dotnet: bool = False,
    pe_vm_like: bool = False,
    force_route: str | None = None,
) -> UnpackRecommendation:
    """Map packer candidates to a future workflow route without executing it."""
    return _attach_stealth(
        _recommend_unpack_route(
            candidates,
            pe_dotnet=pe_dotnet,
            pe_vm_like=pe_vm_like,
            force_route=force_route,
        )
    )


def _recommend_unpack_route(
    candidates: list[JsonObject] | tuple[JsonObject, ...],
    *,
    pe_dotnet: bool = False,
    pe_vm_like: bool = False,
    force_route: str | None = None,
) -> UnpackRecommendation:
    packers = [
        item
        for item in candidates
        if isinstance(item, dict)
        and str(item.get("category", "")) in _PACKER_CATEGORIES
    ]
    names = " | ".join(
        str(item.get("name", "")) + " " + str(item.get("summary", "")) for item in packers
    )

    if force_route is not None:
        route = str(force_route).strip()
        if route not in _ALLOWED_FORCE_ROUTES:
            raise ValueError(
                f"force_route must be one of {sorted(_ALLOWED_FORCE_ROUTES)}; got {force_route!r}"
            )
        hint = (
            "iat_recoverable"
            if route in {"upx", "dotnet"}
            else (
                "vm_coupled_dump_only"
                if route == "bounded_dynamic"
                else None
            )
        )
        return UnpackRecommendation(
            route=route,
            confidence=0.5,
            rationale=(
                f"Caller force_route={route!r} overrides detection routing; "
                "still non-authoritative and claims_universal_unpack remains false."
            ),
            suggested_tools=(
                "unpack.plan",
                "unpack.start",
                "unpack.score_oep",
                "unpack.confirm_oep",
                "unpack.dump_module",
            ),
            candidates=tuple(packers),
            recoverability_hint=hint,
        )

    if pe_dotnet or _DOTNET_NAME.search(names):
        return UnpackRecommendation(
            route="dotnet",
            confidence=0.7 if pe_dotnet else 0.55,
            rationale=(
                "Detection suggests a .NET assembly or managed protector; "
                "use the future M6 .NET path rather than native UPX unpack."
            ),
            suggested_tools=("dotnet.inspect", "dotnet.deobfuscate"),
            candidates=tuple(packers),
        )

    upx_hits = [
        item
        for item in packers
        if _UPX_NAME.search(f"{item.get('name', '')} {item.get('summary', '')}")
    ]
    if upx_hits:
        best = max(
            (float(item.get("confidence", 0.0) or 0.0) for item in upx_hits),
            default=0.0,
        )
        return UnpackRecommendation(
            route="upx",
            confidence=min(1.0, max(best, 0.6)),
            rationale=(
                "Standard UPX candidate detected; try official `unpack.upx.test` then "
                "`unpack.upx.unpack` / `unpack.auto`. Modified UPX stubs may still fail."
            ),
            suggested_tools=(
                "unpack.plan",
                "unpack.start",
                "unpack.upx.test",
                "unpack.upx.unpack",
                "unpack.auto",
            ),
            candidates=tuple(upx_hits),
        )

    if pe_vm_like or _VM_NAME.search(names):
        synthetic: list[JsonObject] = []
        if pe_vm_like and not _VM_NAME.search(names):
            synthetic.append(
                {
                    "category": "protector",
                    "name": "VMProtect-like",
                    "summary": "PE anomalies suggest a VM-style protector (heuristic)",
                    "confidence": 0.4,
                    "source": "builtin.pe_vm_like",
                }
            )
        return UnpackRecommendation(
            route="bounded_dynamic",
            confidence=0.45 if _VM_NAME.search(names) else 0.4,
            rationale=(
                "VM-style protector candidate or PE VM-like anomalies detected; only "
                "bounded runtime analysis and dump attempts are appropriate (M4/M5), "
                "not claimed recovery. Default posture is vm_coupled_dump_only until "
                "unpack.iat.validate reports iat_recoverable. Use force_route when DIE "
                "misses VMP."
            ),
            suggested_tools=(
                "unpack.plan",
                "unpack.start",
                "unpack.score_oep",
                "unpack.confirm_oep",
                "unpack.dump_module",
                "unpack.iat.scan",
                "unpack.iat.validate",
            ),
            candidates=tuple(list(packers) + synthetic),
            # Optimistic IAT recovery is not assumed for VM protectors.
            recoverability_hint="vm_coupled_dump_only",
        )

    if packers:
        return UnpackRecommendation(
            route="generic_dynamic",
            confidence=0.4,
            rationale=(
                "Non-UPX packer/protector candidates present; recommend paused-state "
                "workflow navigation and dump/IAT rebuild (M4/M5), not forced success."
            ),
            suggested_tools=(
                "unpack.plan",
                "unpack.start",
                "workflow.navigate_to_event",
                "unpack.dump_module",
                "unpack.iat.scan",
                "unpack.pe.rebuild",
            ),
            candidates=tuple(packers),
        )

    return UnpackRecommendation(
        route="none",
        confidence=0.2,
        rationale=(
            "No packer/protector/obfuscator candidates; prefer static IDA analysis "
            "unless runtime behavior later contradicts this."
        ),
        suggested_tools=("static.open", "static.functions", "detect.scan"),
        candidates=(),
    )
