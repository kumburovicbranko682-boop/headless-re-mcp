from __future__ import annotations

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
    assert generic.route == "generic_dynamic"
    assert none.route == "none"
    assert none.authoritative is False
    assert "detect.scan" in none.suggested_tools


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

    forced = recommend_unpack_route([], force_route="bounded_dynamic")
    assert forced.route == "bounded_dynamic"
    assert "force_route" in forced.rationale
