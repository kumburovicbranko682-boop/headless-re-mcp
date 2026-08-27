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


def test_apk_components_says_which_list_the_cap_hit() -> None:
    """A combined has_more cannot say which of four lists was truncated.

    Each component list is capped on its own, but the reply used to carry a
    single has_more. With 300 activities and one of everything else, has_more
    is True purely because of activities -- yet an audit reading the full
    receivers list could not tell it was complete rather than a short list
    hidden behind the same flag. The per-list flags name the truncated one.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))

    assert payload["has_more"] is True
    # Only activities overflowed the cap; the other three are whole.
    assert payload["activities_truncated"] is True
    assert payload["services_truncated"] is False
    assert payload["receivers_truncated"] is False
    assert payload["providers_truncated"] is False
    # The combined flag is exactly the OR of the per-list flags.
    assert payload["has_more"] == (
        payload["activities_truncated"]
        or payload["services_truncated"]
        or payload["receivers_truncated"]
        or payload["providers_truncated"]
    )
    doc = _tool_docstring("apk.components")
    assert "activities_truncated" in doc
    assert "providers_truncated" in doc
