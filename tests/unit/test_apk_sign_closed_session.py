"""A retained CLOSED session must not start apksigner."""

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
        self.signs: list[Path] = []

    def sign(
        self,
        source: Path,
        out_apk: Path,
        **kwargs: object,
    ) -> dict[str, Any]:
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK")
        self.signs.append(out_apk)
        return {
            "apk": str(out_apk),
            "size": 2,
            "signed": True,
            "keystore": "debug",
            "debug_keystore": True,
        }


def test_apk_sign_on_a_closed_session_does_not_start_apksigner(tmp_path: Path) -> None:
    """A retained CLOSED session still resolved, so a late sign wrote an APK.

    Measured: after close_session, apk.sign returned ok=True, apksigner ran
    once, and artifact_root/apktool/<id>/signed.apk was written. close_all
    left that file in place because close already ran
    _forget_session_work_dirs. The model then treats the dead session as
    signed.
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

        result = service.apk_sign(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.signs == []
        tree = settings.artifact_root.expanduser().resolve() / "apktool" / session_id
        assert not tree.exists()
    finally:
        service.close_all()


def test_apk_sign_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path,
) -> None:
    """A close mid-sign used to keep the APK after _forget_session_work_dirs."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")

    class _CloseThenSign(_TrackingApktool):
        def sign(  # type: ignore[override]
            self,
            source: Path,
            out_apk: Path,
            **kwargs: object,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().sign(source, out_apk, **kwargs)

    tracker = _CloseThenSign()
    service._apktool_client = lambda: tracker  # type: ignore[method-assign]
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.apk_sign(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        tree = settings.artifact_root.expanduser().resolve() / "apktool" / session_id
        assert not tree.exists()
    finally:
        service.close_all()
