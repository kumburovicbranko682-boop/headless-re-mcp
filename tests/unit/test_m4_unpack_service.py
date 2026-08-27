"""Service-level M4 unpack tool wrappers against FakeDynamicWorker."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
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
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def _service(tmp_path: Path, dynamic: FakeDynamicWorker) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: dynamic,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )


def test_m4_unpack_dump_scan_validate_rebuild(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert dumped.ok and dumped.data is not None
    assert dumped.data["claims_universal_unpack"] is False
    assert dumped.data.get("headers_ok") is True
    dump_path = str(dumped.data["output_path"])

    scanned = service.unpack_iat_scan(session_id, worker.module_base)
    assert scanned.ok and scanned.data is not None
    assert scanned.data["confirmed"] is False
    assert scanned.data["blind_selection"] is False
    # Dedupe-cap disclosure is surfaced so candidates is not read as the full set.
    assert scanned.data["candidates_truncated"] is False
    assert scanned.data["merged_total"] == scanned.data["candidate_count"]
    assert scanned.data["max_candidates"] == 8

    candidate = scanned.data["candidates"][0]
    validated = service.unpack_iat_validate(
        session_id,
        iat_va=int(candidate["iat_va"]),
        size=int(candidate["size"]),
        oep_rva=0x1000,
        module_base=worker.module_base,
    )
    assert validated.ok and validated.data is not None
    assert validated.data["confirmed"] is True

    # Replace dump with a remappable PE image so rebuild can parse it.
    Path(dump_path).write_bytes(binary.read_bytes())
    rebuilt = service.unpack_pe_rebuild(
        session_id,
        dump_path,
        entry_point_rva=0x1000,
        iat_va=int(candidate["iat_va"]),
        iat_size=int(candidate["size"]),
    )
    assert rebuilt.ok and rebuilt.data is not None
    assert rebuilt.data["claims_universal_unpack"] is False
    assert Path(str(rebuilt.data["output_path"])).is_file()

    verified = service.unpack_verify(
        session_id,
        str(rebuilt.data["output_path"]),
        use_die=False,
        open_ida=False,
    )
    assert verified.ok and verified.data is not None
    assert verified.data["claims_universal_unpack"] is False
