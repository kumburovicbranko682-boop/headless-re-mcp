from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

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


@pytest.mark.parametrize("hostile", ["..", ".", "a/b", "x/../y", "", "web/../.."])
def test_dot_segment_ids_are_rejected_at_the_web_and_proxy_guard(
    tmp_path: Path, hostile: str
) -> None:
    """The guard, not a downstream registry.get, must reject traversal ids.

    ``not session_id or Path(session_id).name != session_id`` alone lets ``..``
    through (``Path("..").name == ".."``), which would collapse
    ``artifact_root/web/<id>`` onto the artifact root. Nothing depended on it
    here because the id is also looked up as a session, but a guard that only
    fails closed by luck of a second check is the exact shape the ownership
    traversal fix removed. It must answer invalid_params from the guard itself,
    and never touch the artifact root.
    """
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    try:
        for method, args in (
            (service.web_har_export, ()),
            (service.web_preview, ()),
            (service.proxy_export_har, ()),
            (service.proxy_flow_get, ("flow",)),
        ):
            result = method(hostile, *args)
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_params"
        # Nothing escaped into or above the category roots.
        assert sorted(p.name for p in root.iterdir()) == ["meta"]
    finally:
        service.close_all()
