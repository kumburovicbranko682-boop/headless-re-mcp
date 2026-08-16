"""A retained CLOSED session must not start Ghidra headless analysis."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _TrackingGhidra:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.starts: list[Path] = []

    def analyze_binary(
        self,
        binary: Path,
        project_dir: Path,
        *,
        timeout: float = 120.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        marker = project_dir / "headless-started"
        marker.write_text("started", encoding="utf-8")
        self.starts.append(marker)
        return {
            "project_dir": str(project_dir),
            "stdout_excerpt": "ok",
            "note": "tracked",
        }

    def functions(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        marker = project_dir / "headless-started"
        marker.write_text("started", encoding="utf-8")
        self.starts.append(marker)
        return {
            "items": [{"name": "x", "entry": "0x1000", "body_size": 16}],
            "count": 1,
            "has_more": False,
        }


def test_ghidra_analyze_on_a_closed_session_does_not_start_headless(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED session still resolved, so a late analyze started JVM work.

    Measured: after close_session, ghidra.analyze returned ok=True, analyze_binary
    ran once, and artifact_root/ghidra/<id>/headless-started was written. session.close
    cannot reap a headless run that started after it returned. The model then treats
    the dead session as analyzed and pays ghidra.functions another import.
    """
    tracker = _TrackingGhidra()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.ghidra_analyze(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.starts == []
        project = settings.artifact_root.expanduser().resolve() / "ghidra" / session_id
        assert not project.exists()
    finally:
        service.close_all()


def test_ghidra_analyze_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-analyze used to record a backend on a session that cannot use it."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenAnalyze(_TrackingGhidra):
        def analyze_binary(  # type: ignore[override]
            self,
            binary: Path,
            project_dir: Path,
            *,
            timeout: float = 120.0,
            **kwargs: object,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().analyze_binary(
                binary, project_dir, timeout=timeout, **kwargs
            )

    tracker = _CloseThenAnalyze()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.ghidra_analyze(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()

def test_ghidra_functions_on_a_closed_session_does_not_start_headless(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED session still resolved, so a late export started JVM work.

    Measured: after close_session, ghidra.functions returned ok=True, functions()
    ran once, and artifact_root/ghidra/<id>/headless-started was written. The
    analyze gate does not cover the other ghidra tools; each of them imports
    the binary again under -deleteProject.
    """
    tracker = _TrackingGhidra()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.ghidra_functions(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.starts == []
        project = settings.artifact_root.expanduser().resolve() / "ghidra" / session_id
        assert not project.exists()
    finally:
        service.close_all()


def test_ghidra_functions_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-export used to record a backend on a session that cannot use it."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenExport(_TrackingGhidra):
        def functions(  # type: ignore[override]
            self,
            binary: Path,
            project_dir: Path,
            *,
            limit: int = 256,
            timeout: float = 180.0,
            **kwargs: object,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().functions(
                binary, project_dir, limit=limit, timeout=timeout, **kwargs
            )

    tracker = _CloseThenExport()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.ghidra_functions(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()

