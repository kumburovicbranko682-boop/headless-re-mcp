"""M5 .NET route hands off to real M6 inspect (no deferred stub, no auto-deobfuscate)."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_verified_clr_pe(path: Path) -> None:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_m5_dotnet_route_runs_inspect_not_deferred(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]

    planned = service.unpack_plan(session_id, use_die=False)
    assert planned.ok and planned.data is not None
    assert planned.data["plan"]["route"] == "dotnet"
    assert planned.data["plan"]["backend"] == "m6_dotnet"

    started = service.unpack_start(session_id, use_die=False, execute_upx=False)
    assert started.ok and started.data is not None
    unpack = started.data["unpack"]
    assert unpack["phase"] == "detected"
    assert unpack.get("failure") in (None, {})
    assert any(
        item.get("event") == "routed_m6" for item in unpack.get("timeline") or []
    )
    probe = started.data.get("bounded_probe")
    assert isinstance(probe, dict)
    assert probe["claims_universal_unpack"] is False
    assert probe["clr_verified"] is True
    assert "dotnet.deobfuscate" in probe["next"]

    auto = service.unpack_auto(session_id, use_die=False)
    assert auto.ok and auto.data is not None
    assert auto.data["status"] == "routed_m6"
    assert auto.data["claims_universal_unpack"] is False
    assert auto.data["next"] == ["dotnet.deobfuscate", "dotnet.verify"]
    assert auto.data.get("clr_verified") is True
