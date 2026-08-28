"""apk.intent_filters maps each component's <intent-filter> declarations.

Driven through the _apk seam with a fake APK mimicking androguard's
component getters, get_intent_filters and get_attribute_value.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

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
    def __init__(self) -> None:
        self._filters = {
            ("activity", "com.example.MainActivity"): {
                "action": ["android.intent.action.MAIN"],
                "category": ["android.intent.category.LAUNCHER"],
            },
            ("activity", "com.example.DeepLinkActivity"): {
                "action": ["android.intent.action.VIEW"],
                "category": ["android.intent.category.BROWSABLE"],
                "data": [{"scheme": "myapp", "host": "open"}],
            },
            ("activity", "com.example.PlainActivity"): {},
            ("receiver", "com.example.BootReceiver"): {
                "action": ["android.intent.action.BOOT_COMPLETED"],
            },
        }
        self._exported = {
            "com.example.MainActivity": "true",
            "com.example.DeepLinkActivity": "true",
            "com.example.BootReceiver": None,
        }

    def get_activities(self) -> list[str]:
        return [
            "com.example.MainActivity",
            "com.example.DeepLinkActivity",
            "com.example.PlainActivity",
        ]

    def get_services(self) -> list[str]:
        return []

    def get_receivers(self) -> list[str]:
        return ["com.example.BootReceiver"]

    def get_intent_filters(self, itemtype: str, name: str) -> dict[str, Any]:
        return self._filters.get((itemtype, name), {})

    def get_attribute_value(self, tag: str, attr: str, **kw: Any) -> Any:
        del tag, attr
        return self._exported.get(kw.get("name"))


def _client() -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    return client


def test_intent_filters_only_returns_components_with_filters() -> None:
    payload = _client().intent_filters(Path("d.apk"))
    # MainActivity, DeepLinkActivity, BootReceiver -- PlainActivity is skipped.
    assert payload["total"] == 3
    assert payload["count"] == 3
    names = {c["name"] for c in payload["components"]}
    assert "com.example.PlainActivity" not in names


def test_intent_filters_flag_deep_links_and_schemes() -> None:
    payload = _client().intent_filters(Path("d.apk"))
    by_name = {c["name"]: c for c in payload["components"]}

    deep = by_name["com.example.DeepLinkActivity"]
    assert deep["deep_link"] is True
    assert deep["schemes"] == ["myapp"]
    assert deep["data"] == [{"scheme": "myapp", "host": "open"}]

    main = by_name["com.example.MainActivity"]
    assert main["deep_link"] is False
    assert main["actions"] == ["android.intent.action.MAIN"]
    assert main["categories"] == ["android.intent.category.LAUNCHER"]


def test_intent_filters_report_exported_tri_state() -> None:
    payload = _client().intent_filters(Path("d.apk"))
    by_name = {c["name"]: c for c in payload["components"]}
    assert by_name["com.example.MainActivity"]["exported"] is True
    # A component whose exported attribute is absent reports null, not false.
    assert by_name["com.example.BootReceiver"]["exported"] is None


def test_intent_filters_carry_the_component_type() -> None:
    payload = _client().intent_filters(Path("d.apk"))
    by_name = {c["name"]: c for c in payload["components"]}
    assert by_name["com.example.BootReceiver"]["type"] == "receiver"
    assert by_name["com.example.MainActivity"]["type"] == "activity"


def test_apk_intent_filters_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.intent_filters")
    assert "deep_link" in doc
    assert "exported" in doc
    assert "schemes" in doc
    assert "has_more" in doc
