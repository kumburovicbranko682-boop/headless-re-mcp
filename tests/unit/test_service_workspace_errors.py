"""Coverage for the workspace-profile service methods' failure envelopes.

``test_workspace_profiles.py`` covers the get/set happy paths and the
unknown-profile rejection. These pin the two ``except`` arms that turn an
unexpected failure into a Result envelope instead of raising.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

import headless_re_mcp.core.service_workspace as service_workspace
from headless_re_mcp.core.service_workspace import WorkspaceMixin


class _Host(WorkspaceMixin):
    def __init__(self, settings: Any) -> None:
        self.settings = settings


def test_workspace_mode_get_returns_a_failure_envelope_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(profile: str) -> dict[str, Any]:
        raise RuntimeError("summary blew up")

    monkeypatch.setattr(service_workspace, "profile_summary", _boom)
    host = _Host(types.SimpleNamespace(workspace_profile="full"))

    result = host.workspace_mode_get()

    assert result.ok is False


def test_workspace_mode_set_returns_a_failure_envelope_when_persist_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(values: dict[str, Any]) -> None:
        raise OSError("config volume is read-only")

    monkeypatch.setattr(service_workspace, "update_config_values", _boom)
    host = _Host(types.SimpleNamespace(workspace_profile="full"))

    result = host.workspace_mode_set("android")

    assert result.ok is False
