"""M7 external unpack adapter unit tests (mocked process runners)."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.vmp_dumper import (
    VmpDumperError,
    VmpDumperResult,
    build_vmpdump_argv,
    parse_vmpdump_written_path,
)
from headless_re_mcp.unpack.xvlkc import XvlkcResult


def test_vmpdump_argv_matches_upstream() -> None:
    argv = build_vmpdump_argv(
        Path("VMPDump.exe"),
        pid=0x1234,
        module_name="target.exe",
        entry_point_rva=0x2090,
        disable_reloc=True,
    )
    assert argv == [
        "VMPDump.exe",
        "4660",
        "target.exe",
        "-ep=2090",
        "-disable-reloc",
    ]


def test_vmpdump_parse_written_path() -> None:
    path = parse_vmpdump_written_path(
        "** File written to: C:\\tmp\\foo.VMPDump.exe\n", ""
    )
    assert path == Path(r"C:\tmp\foo.VMPDump.exe")


def test_vmpdump_rejects_file_only_without_pid(tmp_path: Path) -> None:
    from headless_re_mcp.unpack.vmp_dumper import run_vmp_dumper

    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    dumper = tmp_path / "vmpdump.exe"
    dumper.write_bytes(b"MZ")
    out = tmp_path / "out.exe"
    try:
        run_vmp_dumper(
            dumper,
            binary,
            out,
            input_sha256=file_sha256(binary),
        )
        raise AssertionError("expected debuggee_required")
    except VmpDumperError as exc:
        assert exc.code == "debuggee_required"


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x10B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 56, 0x1000, 0x200)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    path.write_bytes(image)


def test_unpack_external_probe_missing(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            xvlkc=None,
            vmp_dumper=None,
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    probed = service.unpack_external_probe(session_id)
    assert probed.ok and probed.data is not None
    assert probed.data["claims_universal_unpack"] is False
    assert probed.data["xvlkc"]["status"] == "missing"
    assert probed.data["vmp_dumper"]["status"] == "missing"
    assert probed.data["scylla"]["status"] == "missing"


def test_unpack_xvlkc_unavailable_when_unset(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            xvlkc=None,
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_xvlkc_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_unpack_xvlkc_mocked(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    xvlkc = tmp_path / "xvlkc.exe"
    xvlkc.write_bytes(b"placeholder")
    artifact_root = tmp_path / "artifacts"

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
    ) -> XvlkcResult:
        del timeout, max_file_size, max_output_size
        assert executable == xvlkc
        assert file_sha256(input_path) == input_sha256
        output_path.write_bytes(input_path.read_bytes())
        return XvlkcResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="ok",
            stderr="",
            duration_ms=1,
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            xvlkc=xvlkc,
        ),
        xvlkc_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_xvlkc_unpack(session_id)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True
    assert Path(result.data["output_path"]).is_file()


def test_unpack_vmp_dump_mocked(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    dumper = tmp_path / "vmpdump.exe"
    dumper.write_bytes(b"placeholder")
    artifact_root = tmp_path / "artifacts"

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
        pid: int | None = None,
        module_name: str | None = None,
        entry_point_rva: int | None = None,
        disable_reloc: bool = False,
        search_roots: list[Path] | None = None,
    ) -> VmpDumperResult:
        del timeout, max_file_size, max_output_size, entry_point_rva, disable_reloc
        del search_roots
        assert executable == dumper
        assert pid == 4242
        assert module_name == "sample.exe"
        output_path.write_bytes(input_path.read_bytes())
        return VmpDumperResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="** Found 3 calls to 2 imports\n** Successfully converted call\nFile written to: x",
            stderr="",
            duration_ms=1,
            dump_ok=True,
            imports_rebuilt=True,
            vm_restored=False,
            pid=4242,
            module_name="sample.exe",
            mode="process",
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            vmp_dumper=dumper,
        ),
        vmp_dumper_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    service.registry.update_metadata(session_id, {"debuggee_pid": 4242})
    result = service.unpack_vmp_dump(session_id)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["dump_ok"] is True
    assert result.data["imports_rebuilt"] is True
    assert result.data["vm_restored"] is False
    assert result.data["pid"] == 4242
    assert result.data["input_unchanged"] is True


def test_unpack_vmp_dump_requires_debuggee(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    dumper = tmp_path / "vmpdump.exe"
    dumper.write_bytes(b"placeholder")
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            vmp_dumper=dumper,
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_vmp_dump(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "debuggee_required"


def test_unpack_vmp_unavailable_when_unset(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            vmp_dumper=None,
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_vmp_dump(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_doctor_reports_xvlkc_and_vmp_missing(tmp_path: Path) -> None:
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            xvlkc=None,
            vmp_dumper=None,
        )
    )
    report = service.doctor().data
    assert report is not None
    probes = {item["name"]: item for item in report["probes"]}
    assert probes["xvlkc"]["status"] == "missing"
    assert probes["vmp_dumper"]["status"] == "missing"
    assert probes["scylla"]["status"] == "missing"


def test_unpack_scylla_unavailable_when_unset(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            scylla=None,
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_scylla_rebuild(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_unpack_scylla_mocked(tmp_path: Path) -> None:
    from headless_re_mcp.unpack.scylla import ScyllaResult

    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    scylla = tmp_path / "Scylla.exe"
    scylla.write_bytes(b"placeholder")
    artifact_root = tmp_path / "artifacts"

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
    ) -> ScyllaResult:
        del timeout, max_file_size, max_output_size
        assert executable == scylla
        assert file_sha256(input_path) == input_sha256
        output_path.write_bytes(input_path.read_bytes())
        return ScyllaResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="ok",
            stderr="",
            duration_ms=1,
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            scylla=scylla,
        ),
        scylla_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.unpack_scylla_rebuild(session_id)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True
    assert Path(result.data["output_path"]).is_file()
    assert "iat-rebuilt" in Path(result.data["output_path"]).name
