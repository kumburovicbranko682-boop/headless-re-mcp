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
        # On Windows the path validator rejects the traversal; elsewhere the
        # capability is refused before it runs. Either way the guarantee under
        # test holds: a hostile session id never creates a directory outside
        # the artifact root.
        if os.name == "nt":
            assert result.error.code == "invalid_request"
        else:
            assert result.error.code == "unsupported_on_platform"
        assert not escaped.exists()
    finally:
        service.close_all()
