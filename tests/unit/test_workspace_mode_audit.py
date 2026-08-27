"""workspace.mode.set must land in the global (session-less) audit log.

workspace.mode.set is a state change (tools/catalog.py): it rewrites the global
work-direction profile, persists it to the user config across restarts, and
changes which tool surface the next MCP connection sees. It owns no session, so
it has no timeline to land in, and it was the one non-PE state change reaching
neither timeline nor audit -- an operator reviewing an unattended run had no
record that the agent reconfigured its own profile. These pin that a persisted
change records a session-less audit entry naming the from/to profiles, that an
invalid profile (a rejected no-op) is not audited, and that an audit-write
failure never fails the mode change itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _service(tmp_path: Path, monkeypatch: Any, profile: str = "full") -> AnalysisService:
    # Redirect the persisted config write to the tmp tree, never the real one.
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: tmp_path / "config.json"
    )
    settings = Settings.load()
    object.__setattr__(settings, "artifact_root", tmp_path / "artifacts")
    object.__setattr__(settings, "workspace_profile", profile)
    return AnalysisService(settings=settings)


def _entries(service: AnalysisService) -> list[JsonObject]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return list(result.data["entries"])


def _by_action(service: AnalysisService, action: str) -> list[JsonObject]:
    return [e for e in _entries(service) if e["action"] == action]


def test_setting_the_profile_records_a_session_less_audit_entry(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service = _service(tmp_path, monkeypatch, "full")
    try:
        result = service.workspace_mode_set("android")
        assert result.ok is True, result.error

        entry = _by_action(service, "workspace.mode.set")[0]
        assert entry["session_id"] is None
        assert entry["ok"] == 1
        assert entry["params_summary"] == {"profile": "android"}
        assert entry["result_summary"] == {"from": "full", "to": "android"}
    finally:
        service.close_all()


def test_an_invalid_profile_is_not_audited(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path, monkeypatch, "full")
    try:
        result = service.workspace_mode_set("nonsense")
        assert result.ok is False
        assert _by_action(service, "workspace.mode.set") == []
    finally:
        service.close_all()


def test_an_audit_write_failure_does_not_fail_the_mode_change(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The profile already persisted; a bookkeeping failure in the audit write
    must not turn a successful mode change into a failed tool call."""
    service = _service(tmp_path, monkeypatch, "full")
    original_repo = getattr(service, "repository", None)

    class _RaisingRepo:
        def append_audit(self, **kwargs: Any) -> None:
            raise RuntimeError("audit store is down")

    try:
        service.repository = _RaisingRepo()  # type: ignore[assignment]
        result = service.workspace_mode_set("web")
        assert result.ok is True
        assert result.data is not None
        assert result.data["profile"] == "web"
        assert service.settings.workspace_profile == "web"
    finally:
        service.repository = original_repo  # type: ignore[assignment]
        service.close_all()
