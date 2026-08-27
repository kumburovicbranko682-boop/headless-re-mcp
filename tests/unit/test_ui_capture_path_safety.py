from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.platform_support import is_windows_host


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
        # On Windows the traversing session id is rejected by the path guard. Off
        # Windows the whole UI-capture surface is unsupported and short-circuits
        # first; either way the call must fail closed and never create the
        # escaped directory outside the artifact root.
        if is_windows_host():
            assert result.error.code == "invalid_request"
        else:
            assert result.error.code == "unsupported_on_platform"
        assert not escaped.exists()
    finally:
        service.close_all()
