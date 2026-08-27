from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.backends.web import WebError
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


def test_dotdot_session_ids_are_rejected_by_the_segment_guard(tmp_path: Path) -> None:
    """The non-PE artifact-dir helpers must reject ``..`` at the guard itself.

    ``Path("..").name == ".."`` slips past the ``name != session_id`` check the
    helpers used, exactly the hole ``_is_safe_session_segment`` was written to
    close for ``_session_artifact_roots``. registry.get backstops the real
    tool flow, but a guard that concedes ``..`` is one refactor away from
    resolving ``<category>/..`` to the artifact root itself. Each helper now
    raises its own invalid_params before touching the registry or the disk.
    """
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    helpers = [
        (service._web_artifact_dir, WebError, "web"),
        (service._proxy_artifact_dir, ProxyError, "proxy"),
        (service._jadx_out_dir, ApkError, "jadx"),
        (service._repack_dir, ApkError, "apktool"),
    ]
    try:
        for segment in ("..", ".", "a/b", ""):
            for helper, error_type, category in helpers:
                with pytest.raises(error_type) as info:
                    helper(segment)
                assert info.value.code == "invalid_params"
                # The guard fires before any category directory is created, so
                # the whole artifact tree stays empty. Probe the category dir
                # itself rather than "<category>/<segment>": for segment ".."
                # the latter is platform-dependent -- POSIX fails the stat
                # because the missing "<category>" cannot be walked, while
                # Windows collapses ".." lexically onto the existing root and
                # reports the escape as real. The category-dir probe means the
                # same thing on both and still proves nothing was written.
                assert not (root / category).exists()
    finally:
        service.close_all()
