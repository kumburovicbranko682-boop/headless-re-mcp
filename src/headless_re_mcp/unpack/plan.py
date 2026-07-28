"""M5 unpack plan builder — routes without claiming success."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.unpack.recommend import UnpackRecommendation, recommend_unpack_route

JsonObject = dict[str, Any]


def build_unpack_plan(
    candidates: list[JsonObject] | tuple[JsonObject, ...],
    *,
    pe_dotnet: bool = False,
    pe_vm_like: bool = False,
    force_route: str | None = None,
    recommendation: UnpackRecommendation | None = None,
) -> JsonObject:
    """Build a non-authoritative unpack plan from detection candidates."""
    rec = recommendation or recommend_unpack_route(
        candidates,
        pe_dotnet=pe_dotnet,
        pe_vm_like=pe_vm_like,
        force_route=force_route,
    )
    route = rec.route
    steps: list[JsonObject]
    if route == "upx":
        steps = [
            {"id": "detect", "tool": "detect.scan", "required": True},
            {"id": "upx_test", "tool": "unpack.upx.test", "required": True},
            {"id": "upx_unpack", "tool": "unpack.upx.unpack", "required": True},
            {"id": "verify", "tool": "unpack.verify", "required": False},
            {"id": "reanalyze", "tool": "static.open", "required": False},
        ]
        backend = "m3_upx"
    elif route == "dotnet":
        steps = [
            {"id": "detect", "tool": "detect.scan", "required": True},
            {"id": "dotnet_inspect", "tool": "dotnet.inspect", "required": True},
            {"id": "dotnet_deobfuscate", "tool": "dotnet.deobfuscate", "required": False},
        ]
        backend = "m6_dotnet"
    elif route == "bounded_dynamic":
        steps = [
            {"id": "detect", "tool": "detect.scan", "required": True},
            {"id": "dynamic_open", "tool": "dynamic.open", "required": True},
            {"id": "navigate", "tool": "workflow.navigate_to_event", "required": False},
            {"id": "oep_score", "tool": "unpack.confirm_oep", "required": True},
            {"id": "dump", "tool": "unpack.dump_module", "required": True},
            {"id": "iat_scan", "tool": "unpack.iat.scan", "required": True},
            {"id": "iat_validate", "tool": "unpack.iat.validate", "required": True},
            {
                "id": "iat_rebuild",
                "tool": "unpack.iat.rebuild",
                "required": False,
                "when": "recoverability == iat_recoverable",
            },
            {"id": "pe_rebuild", "tool": "unpack.pe.rebuild", "required": False},
            {"id": "verify", "tool": "unpack.verify", "required": False},
        ]
        backend = "m4_bounded"
    elif route == "generic_dynamic":
        steps = [
            {"id": "detect", "tool": "detect.scan", "required": True},
            {"id": "dynamic_open", "tool": "dynamic.open", "required": True},
            {"id": "oep_score", "tool": "unpack.confirm_oep", "required": True},
            {"id": "dump", "tool": "unpack.dump_module", "required": True},
            {"id": "iat_scan", "tool": "unpack.iat.scan", "required": True},
            {"id": "pe_rebuild", "tool": "unpack.pe.rebuild", "required": False},
            {"id": "verify", "tool": "unpack.verify", "required": False},
        ]
        backend = "m4_generic"
    else:
        steps = [
            {"id": "detect", "tool": "detect.scan", "required": True},
            {"id": "static", "tool": "static.open", "required": False},
        ]
        backend = "none"

    return {
        "route": route,
        "backend": backend,
        "confidence": rec.confidence,
        "rationale": rec.rationale,
        "recoverability_hint": rec.recoverability_hint,
        "steps": steps,
        "suggested_tools": list(rec.suggested_tools),
        "candidates": [dict(item) for item in rec.candidates],
        "authoritative": False,
        "claims_universal_unpack": False,
        "notes": [
            "Plan does not execute side effects by itself; use unpack.start.",
            "OEP heuristics are never treated as confirmed OEP.",
            "Unsupported routes return observable state without fake success.",
            ".NET route hands off to M6 inspect; deobfuscate remains caller-driven.",
            "bounded_dynamic defaults to vm_coupled_dump_only until iat.validate gates.",
            "UI visible != IAT ready; runnable stage requires explicit UI+PE gates.",
        ],
    }
