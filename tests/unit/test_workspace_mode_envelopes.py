"""workspace.mode.get/set must fail closed as an envelope, never propagate.

The audit tests cover the happy path, the rejected invalid profile, and the
best-effort audit write, but the two `except BaseException` wrappers had no
coverage: workspace.mode.get when summarising the profile faults, and
workspace.mode.set when persisting the new profile faults. These pin that both
turn an unexpected fault into a structured failure envelope, and that a persist
failure leaves the running profile unchanged (the change never took effect, so
it must not be reported as if it had).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path, monkeypatch: Any, profile: str = "full") -> AnalysisService:
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: tmp_path / "config.json"
    )
    settings = Settings.load()
    object.__setattr__(settings, "artifact_root", tmp_path / "artifacts")
    object.__setattr__(settings, "workspace_profile", profile)
    return AnalysisService(settings=settings)


def test_mode_get_fails_closed_on_an_unexpected_fault(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path, monkeypatch, "full")
    try:
        monkeypatch.setattr(
            "headless_re_mcp.core.service_workspace.profile_summary",
            lambda profile: (_ for _ in ()).throw(RuntimeError("summary blew up")),
        )
        result = service.workspace_mode_get()
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_mode_set_reports_a_persist_failure_and_leaves_the_profile_unchanged(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """If persisting the new profile raises, the running profile must stay put
    and the tool must answer with a failure, not a success it did not achieve."""
    service = _service(tmp_path, monkeypatch, "full")
    try:
        def _persist_is_down(values: dict[str, Any]) -> None:
            raise RuntimeError("config volume is read-only")

        monkeypatch.setattr(
            "headless_re_mcp.core.service_workspace.update_config_values", _persist_is_down
        )
        result = service.workspace_mode_set("android")
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
        # The persist failed before the in-process view was mutated.
        assert service.settings.workspace_profile == "full"
        # A change that never took effect must not be audited.
        rows = service.audit_list(None)
        assert rows.ok and rows.data is not None
        assert [e for e in rows.data["entries"] if e["action"] == "workspace.mode.set"] == []
    finally:
        service.close_all()
