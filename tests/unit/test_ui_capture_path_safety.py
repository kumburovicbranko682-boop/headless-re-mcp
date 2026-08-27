from __future__ import annotations

import os
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
        # On Windows the capture path runs and the session-id guard rejects the
        # traversal as invalid_request; off Windows the capability is gated out
        # first, so the honest answer is unsupported_on_platform. Either way the
        # traversal must never materialize a directory outside artifact_root --
        # that no-escape invariant is the real subject of this test.
        if os.name == "nt":
            assert result.error.code == "invalid_request"
        else:
            assert result.error.code == "unsupported_on_platform"
        assert not escaped.exists()
    finally:
        service.close_all()
