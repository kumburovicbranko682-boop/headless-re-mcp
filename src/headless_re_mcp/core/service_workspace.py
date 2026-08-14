"""Workspace-profile service methods (the startup work direction).

Reading the profile is cheap. Setting it persists to the user config so the
choice survives restarts; the running MCP surface only changes on the next
connection because a client's tool list is fixed for a session.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.config import Settings, update_config_values
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.results import _failure, _success
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
            update_config_values({"workspace_profile": normalized})
            # Settings is frozen; mutate the process view so a same-process web
            # UI reflects the change immediately, and persist for next start.
            object.__setattr__(self.settings, "workspace_profile", normalized)
            summary = profile_summary(normalized)
            summary["note"] = "MCP clients see the new tool surface on their next connection"
            summary["persisted"] = True
            return _success(summary)
        except BaseException as exc:
            return _failure(exc)
