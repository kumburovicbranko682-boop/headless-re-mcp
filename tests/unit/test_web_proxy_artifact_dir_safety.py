from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# Every service method that turns a caller-supplied session_id into a
# filesystem path under the artifact root, with the read args each needs.
_ARTIFACT_DIR_METHODS = [
    ("web_preview", ()),
    ("web_network_get", ("request",)),
    ("web_script_source", ("script",)),
    ("web_screenshot", ()),
    ("web_har_export", ()),
    ("proxy_flow_get", ("flow",)),
    ("proxy_export_har", ()),
]


def _tree(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {str(path.relative_to(root)) for path in root.rglob("*")}


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


def test_traversal_shaped_session_ids_are_refused_before_touching_disk(
    tmp_path: Path,
) -> None:
    """A session_id that is not a bare name is a path-escape attempt.

    The unknown-session test above uses valid bare names, so it exercises the
    registry-miss branch, not the guard that keeps the id from being spliced
    into ``artifact_root / web|proxy / <id>``. A caller-supplied id with a
    separator, a ``..`` component, or an absolute root would otherwise let the
    mkdir land outside the session's own tree. Each such id must be rejected as
    invalid_params -- before the registry lookup and before any directory is
    created -- and leave the artifact root byte-for-byte unchanged.
    """
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    # POSIX-only separators: a backslash is a legal single-component name on
    # POSIX, so it is not a traversal vector here and would miss this guard.
    hostile_ids = ["", ".", "..", "../../etc", "a/b", "web/../../secret", "/etc/passwd"]
    try:
        baseline = _tree(root)
        for session_id in hostile_ids:
            for name, args in _ARTIFACT_DIR_METHODS:
                method = getattr(service, name)
                result = method(session_id, *args)
                assert result.ok is False, (session_id, name)
                assert result.error is not None
                assert result.error.code == "invalid_params", (session_id, name, result.error)
                assert "session id" in result.error.message
        # Nothing was created anywhere under the root...
        assert _tree(root) == baseline
        # ...and no id climbed out to the escape target ../../etc resolves to.
        assert not (tmp_path / "etc").exists()
        assert not (root.parent / "secret").exists()
    finally:
        service.close_all()
