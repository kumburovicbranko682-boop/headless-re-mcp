from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


@pytest.mark.parametrize("method_name", ["ui_screenshot", "ui_ocr"])
@pytest.mark.parametrize("hostile", ["../../escaped", "..", ".", ""])
def test_invalid_ui_capture_session_cannot_create_directories_outside_artifacts(
    tmp_path: Path,
    method_name: str,
    hostile: str,
) -> None:
    """Hostile ids are judged before the platform gate, on every host.

    A bare ``..`` matters separately from ``../../escaped``: the old
    ``Path(id).name != id`` guard passed it, resolving ``ui/..`` to the
    artifact root itself. And the id check must come before the Windows-only
    gate, or Linux reports unsupported_on_platform for input that is simply
    invalid and the path guard goes untested on the platform CI runs on.
    """
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
        result = method(hostile, 1)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert not escaped.exists()
    finally:
        service.close_all()
