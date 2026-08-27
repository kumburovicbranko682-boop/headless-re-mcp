from __future__ import annotations

import pytest

from headless_re_mcp.unpack.recommend import recommend_unpack_route


def test_recommend_upx_route_is_non_authoritative() -> None:
    result = recommend_unpack_route(
        [
            {
                "category": "packer",
                "name": "UPX",
                "summary": "Packer: UPX(4.2)",
                "confidence": 0.9,
            }
        ]
    )

    assert result.route == "upx"
    assert result.authoritative is False
    assert result.confidence >= 0.6
    assert result.stealth_profile is None
    assert "dynamic.stealth.set" not in result.suggested_tools
    assert "unpack.upx.test" in result.suggested_tools
    assert "unpack.auto" in result.suggested_tools


def test_recommend_dotnet_route_from_pe_flag_or_name() -> None:
    from_flag = recommend_unpack_route([], pe_dotnet=True)
    from_name = recommend_unpack_route(
        [{"category": "protector", "name": ".NET Reactor", "summary": "dnlib"}]
    )

    assert from_flag.route == "dotnet"
    assert from_name.route == "dotnet"
    assert from_flag.authoritative is False
    assert "dotnet.deobfuscate" in from_flag.suggested_tools


def test_recommend_vm_and_generic_and_none_routes() -> None:
    vm = recommend_unpack_route(
        [{"category": "protector", "name": "VMProtect", "summary": "vmp"}]
    )
    generic = recommend_unpack_route(
        [{"category": "packer", "name": "ASPack", "summary": "Packer: ASPack"}]
    )
    none = recommend_unpack_route(
        [{"category": "compiler", "name": "MSVC", "summary": "Compiler"}]
    )

    assert vm.route == "bounded_dynamic"
    assert vm.stealth_profile == "vmp"
    assert vm.suggested_tools[0] == "dynamic.stealth.set"
    assert "dynamic.launch" in vm.suggested_tools
    assert generic.route == "generic_dynamic"
    assert none.route == "none"
    assert none.authoritative is False
    assert "detect.scan" in none.suggested_tools
    themida = recommend_unpack_route(
        [{"category": "protector", "name": "Themida", "summary": "WinLicense / TMD"}]
    )
    assert themida.stealth_profile == "themida"
    assert themida.suggested_tools[0] == "dynamic.stealth.set"


def test_recommend_pe_vm_like_and_force_route() -> None:
    from headless_re_mcp.unpack.recommend import pe_suggests_vm_protector

    assert pe_suggests_vm_protector(section_names=(".vmp0", "CODE")) is True
    assert pe_suggests_vm_protector(
        finding_ids=(
            "builtin:anomaly:high-entropy:.vmp1",
            "builtin:anomaly:sparse-imports",
            "builtin:anomaly:virtual-raw-gap:.vmp1",
        )
    )
    vm_like = recommend_unpack_route([], pe_vm_like=True)
    assert vm_like.route == "bounded_dynamic"
    assert any(item.get("name") == "VMProtect-like" for item in vm_like.candidates)
    assert vm_like.stealth_profile == "vmp"

    forced = recommend_unpack_route([], force_route="bounded_dynamic")
    assert forced.route == "bounded_dynamic"
    assert "force_route" in forced.rationale


def test_force_route_rejects_a_route_outside_the_allowed_set() -> None:
    # A caller override is only honoured for known routes; an unknown one is a
    # request error, not a silent pass-through that later routing must second-guess.
    with pytest.raises(ValueError, match="force_route must be one of"):
        recommend_unpack_route([], force_route="magic")
