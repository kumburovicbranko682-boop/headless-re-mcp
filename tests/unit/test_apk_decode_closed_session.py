"""A retained CLOSED session must not start apktool decode."""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _TrackingApktool:
    def __init__(self) -> None:
        self.decodes: list[Path] = []

    def decode(
        self,
        apk: Path,
        out_dir: Path,
        *,
        timeout: float = 600.0,
        no_resources: bool = False,
    ) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        marker = out_dir / "apktool-started"
        marker.write_text("started", encoding="utf-8")
        self.decodes.append(marker)
        return {
            "decoded_dir": str(out_dir),
            "manifest": "AndroidManifest.xml",
            "smali_dirs": ["smali"],
            "has_resources": False,
        }


def test_apk_decode_on_a_closed_session_does_not_start_apktool(tmp_path: Path) -> None:
    """A retained CLOSED session still resolved, so a late decode wrote a tree.

    Measured: after close_session, apk.decode returned ok=True, apktool ran
    once, and artifact_root/apktool/<id>/decoded/apktool-started was written.
    close_all left that tree in place because close already ran
    _forget_session_work_dirs. The model then treats the dead session as
    decoded and pays apk.repack against an unreclaimable tree.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    tracker = _TrackingApktool()
    service._apktool_client = lambda: tracker  # type: ignore[method-assign]
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.decodes == []
        tree = settings.artifact_root.expanduser().resolve() / "apktool" / session_id
        assert not tree.exists()
    finally:
        service.close_all()


def test_apk_decode_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path,
) -> None:
    """A close mid-decode used to keep the tree after _forget_session_work_dirs."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")

    class _CloseThenDecode(_TrackingApktool):
        def decode(  # type: ignore[override]
            self,
            apk: Path,
            out_dir: Path,
            *,
            timeout: float = 600.0,
            no_resources: bool = False,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().decode(
                apk, out_dir, timeout=timeout, no_resources=no_resources
            )

    tracker = _CloseThenDecode()
    service._apktool_client = lambda: tracker  # type: ignore[method-assign]
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_decode(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        tree = settings.artifact_root.expanduser().resolve() / "apktool" / session_id
        assert not tree.exists()
    finally:
        service.close_all()
