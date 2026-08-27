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


class _ManifestApk:
    """One of each rule: explicit true/false, filter-implied, provider defaults."""

    def get_activities(self) -> list[str]:
        return ["b.Act", "a.Act"]

    def get_services(self) -> list[str]:
        return ["s.Svc"]

    def get_receivers(self) -> list[str]:
        return ["r.Rcv"]

    def get_providers(self) -> list[str]:
        return ["p.Prov", "q.Prov"]

    def get_main_activity(self) -> str:
        return "a.Act"

    def get_attribute_value(self, tag: str, attribute: str, **kwargs: str) -> str | None:
        assert attribute == "exported"
        explicit = {
            ("activity", "a.Act"): "true",
            ("activity", "b.Act"): "false",
            ("provider", "p.Prov"): "true",
        }
        return explicit.get((tag, kwargs.get("name", "")))

    def get_intent_filters(self, itemtype: str, name: str) -> dict[str, list[str]]:
        if (itemtype, name) == ("receiver", "r.Rcv"):
            return {"action": ["android.intent.action.BOOT_COMPLETED"], "category": []}
        return {"action": [], "category": [], "data": []}


class _UnreadableManifestApk(_ManifestApk):
    def get_attribute_value(self, tag: str, attribute: str, **kwargs: str) -> str | None:
        raise RuntimeError("manifest attribute lookup broke")


def test_apk_components_reports_which_components_are_exported() -> None:
    """exported_* answer the attack-surface question the name lists cannot.

    Explicit android:exported wins (a.Act true, b.Act false, p.Prov true);
    without it a filtered receiver counts as exported (pre-targetSdk-31
    default: r.Rcv), an unfiltered service and an attribute-less provider do
    not (s.Svc, q.Prov).
    """
    client = ApkClient()
    client._apk = lambda _path: _ManifestApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert payload["exported_activities"] == ["a.Act"]
    assert payload["exported_services"] == []
    assert payload["exported_receivers"] == ["r.Rcv"]
    assert payload["exported_providers"] == ["p.Prov"]
    doc = _tool_docstring("apk.components")
    assert "exported_activities" in doc


def test_apk_components_omits_exported_when_the_manifest_cannot_be_read() -> None:
    """A failed lookup omits all four fields rather than guessing not-exported.

    A partial or empty exported list after a lookup failure would read as "no
    attack surface" -- a false negative. The four base name lists must still
    come back.
    """
    client = ApkClient()
    client._apk = lambda _path: _UnreadableManifestApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert "exported_activities" not in payload
    assert "exported_services" not in payload
    assert "exported_receivers" not in payload
    assert "exported_providers" not in payload
    assert payload["activities"] == ["a.Act", "b.Act"]
