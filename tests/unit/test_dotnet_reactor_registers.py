"""A NETReactorSlayer output must enter the artifacts table so retention can see it."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    NetReactorSlayerResult,
)
from tests.unit.test_dotnet_de4dot import _write_verified_clr_pe


def test_dotnet_reactor_unpack_timeout_stays_retryable(tmp_path: Path) -> None:
    """A NETReactorSlayer timeout must reach the caller with retryable=True.

    The error marks a timeout retryable like its siblings, but the dotnet
    handler dropped the flag when translating to the RpcError envelope, so an
    unattended caller treated a transient unpack timeout as permanent.
    """
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    nrs = tmp_path / "NETReactorSlayer.CLI.exe"
    nrs.write_bytes(b"placeholder")

    def timing_out_runner(*args: object, **kwargs: object) -> object:
        raise NetReactorSlayerError(
            NetReactorSlayerErrorCode.TIMEOUT, "slayer timed out", retryable=True
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            net_reactor_slayer=nrs,
        ),
        net_reactor_slayer_runner=timing_out_runner,
    )
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        result = service.dotnet_reactor_unpack(session_id)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "timeout"
        assert result.error.retryable is True
    finally:
        service.close_all()


def test_dotnet_reactor_unpack_registers_the_image_so_gc_can_see_it(tmp_path: Path) -> None:
    """A successful slayer run wrote a PE that artifacts.list and gc could not see.

    Measured: dotnet.reactor.unpack returned ok=True and a 2048-byte
    artifact_root/dotnet/<id>/nrs-*.exe. artifacts.list total was 0.
    gc_artifacts(max_total_bytes=1) removed 0. close_session and close_all
    left the file.
    """
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    nrs = tmp_path / "NETReactorSlayer.CLI.exe"
    nrs.write_bytes(b"placeholder")

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        **kwargs: object,
    ) -> NetReactorSlayerResult:
        output_path.write_bytes(input_path.read_bytes())
        return NetReactorSlayerResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=file_sha256(input_path),
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
            artifact_root=tmp_path / "artifacts",
            net_reactor_slayer=nrs,
        ),
        net_reactor_slayer_runner=fake_runner,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.dotnet_reactor_unpack(session_id)
        assert result.ok and result.data is not None, result.error
        out = Path(str(result.data["net_reactor_slayer"]["output_path"]))
        assert out.is_file()
        assert out.stat().st_size == 2048
        assert result.data.get("artifact_id")

        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None, listed.error
        assert listed.data["total"] == 1
        row = listed.data["artifacts"][0]
        assert Path(str(row["path"])) == out
        assert int(row["size"]) == 2048
        assert row["kind"] == "dotnet_reactor_unpacked"

        newer = service.settings.artifact_root.expanduser().resolve() / "newer.bin"
        newer.write_bytes(b"x" * 4096)
        service.record_artifact(
            session_id=session_id,
            kind="probe",
            path=newer,
            sha256="ab",
            source="test",
        )
        collected = service.repository.gc_artifacts(max_total_bytes=1)
        assert collected["count"] >= 1
        assert not out.is_file()
    finally:
        service.close_all()
