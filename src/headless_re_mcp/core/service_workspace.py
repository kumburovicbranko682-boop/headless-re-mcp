"""Workspace-profile service methods (the startup work direction).

Reading the profile is cheap. Setting it persists to the user config so the
choice survives restarts; the running MCP surface only changes on the next
connection because a client's tool list is fixed for a session.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from headless_re_mcp.config import Settings, update_config_values
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _ensure_repository
from headless_re_mcp.core.workspace import PROFILES, profile_summary

JsonObject = dict[str, Any]


class WorkspaceMixin:
    settings: Settings

    def workspace_mode_get(self) -> Result[JsonObject]:
        try:
            profile = getattr(self.settings, "workspace_profile", "full")
            return _success(profile_summary(profile))
        except BaseException as exc:
            return _failure(exc)

    def workspace_mode_set(self, profile: str) -> Result[JsonObject]:
        try:
            normalized = str(profile).strip().lower()
            if normalized not in PROFILES:
                choices = ", ".join(PROFILES)
                return _failure(
                    ValueError(f"unknown workspace profile '{profile}'; choose one of {choices}")
                )
            previous = str(getattr(self.settings, "workspace_profile", "full"))
            update_config_values({"workspace_profile": normalized})
            # Settings is frozen; mutate the process view so a same-process web
            # UI reflects the change immediately, and persist for next start.
            object.__setattr__(self.settings, "workspace_profile", normalized)
            summary = profile_summary(normalized)
            summary["note"] = "MCP clients see the new tool surface on their next connection"
            summary["persisted"] = True
            self._audit_workspace_mode(previous, normalized)
            return _success(summary)
        except BaseException as exc:
            return _failure(exc)

    def _audit_workspace_mode(self, previous: str, current: str) -> None:
        """Record a persisted workspace-profile change in the audit log.

        workspace.mode.set is the one non-PE state change that owns no session
        and touches no device: it rewrites a global config value that persists
        across restarts and changes which tool surface the next MCP connection
        sees. That is a privileged self-reconfiguration an operator reviewing an
        unattended run should be able to see, yet it reached neither a timeline
        (there is no session) nor the audit log. Like device.* it lands
        session-less (session_id=None), best-effort so a bookkeeping failure
        cannot undo a change that already persisted, and it records only the
        profile names -- drawn from a fixed set, so no secrets -- as from/to.
        """
        with suppress(Exception):
            _ensure_repository(self).append_audit(
                session_id=None,
                action="workspace.mode.set",
                params_summary={"profile": current},
                ok=True,
                result_summary={"from": previous, "to": current},
            )
