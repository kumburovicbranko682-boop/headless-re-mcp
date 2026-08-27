from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


@pytest.mark.parametrize("method_name", ["ui_screenshot", "ui_ocr"])
def test_invalid_ui_capture_session_cannot_create_directories_outside_artifacts(
    tmp_path: Path,
    method_name: str,
) -> None:
    artifact_root = tmp_path / "artifacts"
    service = AnalysisService(
        replace(
            Settings.load(tmp_path / "missing-config.json"),
            artifact_root=artifact_root,
        )
    )
    escaped = tmp_path / "escaped"

    try:
        method = getattr(service, method_name)
        result = method("../../escaped", 1)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert not escaped.exists()
    finally:
        service.close_all()


@pytest.mark.parametrize("method_name", ["ui_screenshot", "ui_ocr"])
@pytest.mark.parametrize("session_id", ["..", ".", ""])
def test_dot_segment_ui_capture_sessions_are_invalid_on_every_platform(
    tmp_path: Path,
    method_name: str,
    session_id: str,
) -> None:
    """``..`` passes ``Path(session_id).name != session_id`` and would resolve
    ``ui/<session>`` onto the artifact root itself; the guard must reject it
    before the platform gate answers, so the contract is identical on Windows
    and POSIX."""
    artifact_root = tmp_path / "artifacts"
    service = AnalysisService(
        replace(
            Settings.load(tmp_path / "missing-config.json"),
            artifact_root=artifact_root,
        )
    )

    try:
        method = getattr(service, method_name)
        result = method(session_id, 1)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert not (artifact_root / "ui").exists()
    finally:
        service.close_all()
