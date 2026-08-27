"""unpack.pe.rebuild must not let a traversal session_id escape the artifact root.

``unpack_pe_rebuild`` builds ``artifact_root/unpack/<session_id>`` and mkdir+writes
the rebuilt PE there. It only calls imports.read -- the one step that resolves the
session against a live runtime -- when iat_va/iat_size are both supplied. With them
omitted, a session_id like ``../../escape`` reached the join unchecked, so the
rebuilt image landed outside the artifact root. These tests pin the fail-closed
guard on both rebuild writers.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


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
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def test_pe_rebuild_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        artifact_root = settings.artifact_root.expanduser().resolve()
        dump = artifact_root / "dump.exe"
        dump.write_bytes(binary.read_bytes())

        # "../../escape" would resolve to tmp_path/escape (two levels above
        # artifact_root/unpack); no iat_va/iat_size so imports.read is skipped.
        result = service.unpack_pe_rebuild("../../escape", str(dump), entry_point_rva=0x1000)

        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
        # The strongest invariant: nothing was written outside the artifact root.
        assert not (tmp_path / "escape").exists()
        assert list(tmp_path.glob("**/pe-rebuilt-*.exe")) == []
    finally:
        service.close_all()


def test_pe_rebuild_still_writes_inside_the_root_for_a_valid_session(tmp_path: Path) -> None:
    """The guard must not reject an ordinary (uuid) session id."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        artifact_root = settings.artifact_root.expanduser().resolve()
        dump = artifact_root / "dump.exe"
        dump.write_bytes(binary.read_bytes())

        result = service.unpack_pe_rebuild(session_id, str(dump), entry_point_rva=0x1000)

        assert result.ok and result.data is not None, result.error
        out = Path(str(result.data["output_path"])).resolve()
        assert out.is_file()
        # Written under the owned artifact subtree, not somewhere upstream.
        assert artifact_root in out.parents
    finally:
        service.close_all()


def test_iat_rebuild_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        artifact_root = settings.artifact_root.expanduser().resolve()
        dump = artifact_root / "dump.exe"
        dump.write_bytes(binary.read_bytes())

        result = service.unpack_iat_rebuild("../../escape", str(dump), iat_va=0x2000, size=0x40)

        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
        assert not (tmp_path / "escape").exists()
    finally:
        service.close_all()
