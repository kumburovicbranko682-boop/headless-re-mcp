from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def test_unknown_sessions_cannot_create_web_or_proxy_artifact_directories(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    calls = [
        ("web-preview", service.web_preview, ()),
        ("web-network", service.web_network_get, ("request",)),
        ("web-script", service.web_script_source, ("script",)),
        ("web-shot", service.web_screenshot, ()),
        ("web-har", service.web_har_export, ()),
        ("proxy-flow", service.proxy_flow_get, ("flow",)),
        ("proxy-har", service.proxy_export_har, ()),
    ]
    try:
        for session_id, method, args in calls:
            result = method(session_id, *args)
            assert result.ok is False
            assert not (root / "web" / session_id).exists()
            assert not (root / "proxy" / session_id).exists()
    finally:
        service.close_all()
