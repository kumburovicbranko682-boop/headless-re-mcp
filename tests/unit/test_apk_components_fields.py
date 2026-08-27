"""apk.components descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

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
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
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


class _UnsortedApk:
    """A manifest whose activities exceed the cap in a non-alphabetical order.

    androguard yields components in manifest declaration order, so a capped view
    that keeps the first cap declarations and sorts only those is a sorted slice
    of an arbitrary subset, not the alphabetically-first cap.
    """

    def get_activities(self) -> list[str]:
        return ["c.Z", "c.M", "c.A", "c.B", "c.K", "c.C"]

    def get_services(self) -> list[str]:
        return []

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []

    def get_main_activity(self) -> str:
        return "c.A"


def test_apk_components_capped_list_is_the_alphabetical_prefix() -> None:
    """A capped component list must be the alphabetically-first cap, deterministically.

    The shared cap helper used to keep the first cap names in manifest order and
    sort only those, so a large app's activity list was a sorted view of whichever
    activities were declared first. Force a non-alphabetical declaration order,
    cap to three, and require the alphabetical prefix with an honest has_more.
    """
    from headless_re_mcp.backends.apk import client as mod

    monkeypatched = mod.ApkClient()
    monkeypatched._apk = lambda _path: _UnsortedApk()  # type: ignore[method-assign]
    monkeypatched_cap = 3
    original = mod._MAX_COMPONENT_NAMES
    mod._MAX_COMPONENT_NAMES = monkeypatched_cap
    try:
        payload = monkeypatched.components(Path("dummy.apk"))
    finally:
        mod._MAX_COMPONENT_NAMES = original
    assert payload["activities"] == ["c.A", "c.B", "c.C"]
    assert payload["has_more"] is True
