"""An IAT-rebuilt PE must enter the artifacts table so retention can see it."""

from __future__ import annotations

from pathlib import Path

from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild


def test_unpack_iat_rebuild_registers_the_image_so_gc_can_see_it(tmp_path: Path) -> None:
    """A successful IAT rebuild wrote a PE that artifacts.list and gc could not see.

    Measured: unpack.iat.rebuild returned ok=True and a 2048-byte
    artifact_root/unpack/<id>/iat-rebuilt-*.exe. artifacts.list total was 0.
    gc_artifacts(max_total_bytes=1) removed 0. close_session and close_all
    left the file.
    """
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    try:
        rebuilt = service.unpack_iat_rebuild(
            session_id,
            str(dump_file),
            iat_va=worker.module_base + 0x2000,
            size=0x20,
            oep_rva=0x1000,
        )
        assert rebuilt.ok and rebuilt.data is not None, rebuilt.error
        out = Path(str(rebuilt.data["output_path"]))
        assert out.is_file()
        assert out.stat().st_size == 2048
        assert rebuilt.data.get("artifact_id")

        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None, listed.error
        assert listed.data["total"] == 1
        row = listed.data["artifacts"][0]
        assert Path(str(row["path"])) == out
        assert int(row["size"]) == 2048
        assert row["kind"] == "iat_rebuilt"

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
