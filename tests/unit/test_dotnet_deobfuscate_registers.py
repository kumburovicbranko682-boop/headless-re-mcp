"""A de4dot output must enter the artifacts table so retention can see it."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import De4dotResult
from tests.unit.test_dotnet_de4dot import _write_verified_clr_pe


def test_dotnet_deobfuscate_registers_the_image_so_gc_can_see_it(tmp_path: Path) -> None:
    """A successful de4dot run wrote a PE that artifacts.list and gc could not see.

    Measured: dotnet.deobfuscate returned ok=True and a 2048-byte
    artifact_root/dotnet/<id>/de4dot-*.exe. artifacts.list total was 0.
    gc_artifacts(max_total_bytes=1) removed 0. close_session and close_all
    left the file.
    """
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        **kwargs: object,
    ) -> De4dotResult:
        output_path.write_bytes(input_path.read_bytes())
        return De4dotResult(
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
            de4dot=de4dot,
        ),
        de4dot_runner=fake_runner,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.dotnet_deobfuscate(session_id)
        assert result.ok and result.data is not None, result.error
        out = Path(str(result.data["de4dot"]["output_path"]))
        assert out.is_file()
        assert out.stat().st_size == 2048
        assert result.data.get("artifact_id")

        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None, listed.error
        assert listed.data["total"] == 1
        row = listed.data["artifacts"][0]
        assert Path(str(row["path"])) == out
        assert int(row["size"]) == 2048
        assert row["kind"] == "dotnet_deobfuscated"

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
