"""apk.components descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _FakeApk:
    def get_activities(self) -> list[str]:
        return [f"A{index}" for index in range(300)]

    def get_services(self) -> list[str]:
        return ["S"]

    def get_receivers(self) -> list[str]:
        return ["R"]

    def get_providers(self) -> list[str]:
        return ["P"]

    def get_main_activity(self) -> str:
        return "A0"


def test_apk_components_names_the_four_lists_not_components() -> None:
    """The catalog never named the payload or the cap.

    Measured: 300 activities, cap 256 -> 256 activities, has_more True.
    There is no components field. Looking for components after a successful
    call reads as no UI entry points, and a full 256 list with no has_more
    reads as every activity.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign, assignment]
    payload = client.components(Path("dummy.apk"))
    assert "components" not in payload
    assert len(payload["activities"]) == 256
    assert payload["has_more"] is True
    assert payload["main_activity"] == "A0"
    assert payload["services"] == ["S"]
    doc = _tool_docstring("apk.components")
    assert "Answers with activities" in doc
    assert "has_more" in doc
    assert "main_activity" in doc


class _FakeApkLists:
    def __init__(
        self,
        *,
        activities: list[str],
        services: list[str],
        receivers: list[str],
        providers: list[str],
    ) -> None:
        self._activities = activities
        self._services = services
        self._receivers = receivers
        self._providers = providers

    def get_activities(self) -> list[str]:
        return self._activities

    def get_services(self) -> list[str]:
        return self._services

    def get_receivers(self) -> list[str]:
        return self._receivers

    def get_providers(self) -> list[str]:
        return self._providers

    def get_main_activity(self) -> str:
        return self._activities[0] if self._activities else ""


def _components_over(fake: _FakeApkLists) -> dict[str, Any]:
    client = ApkClient()
    client._apk = lambda _path: fake  # type: ignore[method-assign, assignment]
    return client.components(Path("dummy.apk"))


def test_per_list_has_more_flags_only_the_list_that_filled_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """has_more OR's four lists; the per-list flags say which one truncated.

    Cap the component lists low, then overflow only receivers. The combined
    has_more used to be all a caller got, so it could not tell three complete
    lists from the one truncated receivers list -- the exact thing the
    docstring promised. receivers_has_more must be True while the other three
    stay False, and the combined has_more must still be True.
    """
    monkeypatch.setattr(apk_client, "_MAX_COMPONENT_NAMES", 2)
    payload = _components_over(
        _FakeApkLists(
            activities=["a.A"],
            services=["s.A"],
            receivers=["r.A", "r.B", "r.C"],
            providers=["p.A"],
        )
    )
    assert payload["receivers_has_more"] is True
    assert payload["activities_has_more"] is False
    assert payload["services_has_more"] is False
    assert payload["providers_has_more"] is False
    assert payload["has_more"] is True


def test_no_list_over_the_cap_leaves_every_flag_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When nothing truncates, the combined and all per-list flags are False."""
    monkeypatch.setattr(apk_client, "_MAX_COMPONENT_NAMES", 8)
    payload = _components_over(
        _FakeApkLists(
            activities=["a.A", "a.B"],
            services=["s.A"],
            receivers=["r.A"],
            providers=["p.A"],
        )
    )
    assert payload["has_more"] is False
    assert payload["activities_has_more"] is False
    assert payload["services_has_more"] is False
    assert payload["receivers_has_more"] is False
    assert payload["providers_has_more"] is False
