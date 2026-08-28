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


class _ReverseOrderApk:
    """A manifest that declares 300 activities in reverse-sorted order.

    Names are zero-padded so lexicographic order matches numeric order, and the
    list is handed back A299-first, so the alphabetically-early activities sit
    past the 256 cap in declaration order -- exactly the case the sort-before-cap
    fix is about.
    """

    def get_activities(self) -> list[str]:
        return [f"A{index:03d}" for index in range(299, -1, -1)]

    def get_services(self) -> list[str]:
        return []

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []

    def get_main_activity(self) -> str:
        return "A000"


def test_apk_components_returns_the_alphabetical_head_not_the_declaration_head() -> None:
    """A manifest past the cap returns the alphabetically-first names, not decl order.

    androguard hands the component lists back fully materialized in manifest
    declaration order. The old code capped to the first 256 in that order and
    sorted only those, so a large manifest (>256 activities) returned the
    declaration-order-first 256 alphabetized -- silently dropping alphabetically-
    early activities declared past the cap. Here activities arrive reverse-sorted,
    so the 256-item page must start at A000 (the true head), not A044 (the head of
    the reverse-order prefix alphabetized). Same sort-before-window contract
    apk.classes and adb.packages keep.
    """
    client = ApkClient()
    client._apk = lambda _path: _ReverseOrderApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert len(payload["activities"]) == 256
    assert payload["has_more"] is True
    assert payload["activities"] == [f"A{index:03d}" for index in range(256)]


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
