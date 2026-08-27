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

        # The property under test holds on every host: a traversal session id
        # never creates a directory outside the artifact root.
        assert result.ok is False
        assert result.error is not None
        assert not escaped.exists()
        if is_windows_host():
            # Windows validates the session id and rejects the traversal.
            assert result.error.code == "invalid_request"
        else:
            # UI capture is Windows-only; the platform gate fails closed before
            # any path handling, so nothing is created outside artifacts either.
            assert result.error.code == "unsupported_on_platform"
    finally:
        service.close_all()
