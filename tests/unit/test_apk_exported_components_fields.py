"""apk.exported_components folds components into the externally-reachable surface.

Driven through the _apk seam with a fake APK mimicking androguard's component
getters, get_intent_filters and get_attribute_value.
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
            ("receiver", "com.example.BootReceiver"): {
                "action": ["android.intent.action.BOOT_COMPLETED"],
            },
            ("activity", "com.example.DeepLinkActivity"): {
                "action": ["android.intent.action.VIEW"],
                "data": [{"scheme": "myapp"}],
            },
        }
        # (name, attr) -> value; absent keys return None.
        self._attrs = {
            ("com.example.MainActivity", "exported"): "true",
            ("com.example.SecretService", "exported"): "false",
            ("com.example.GuardedActivity", "exported"): "true",
            ("com.example.GuardedActivity", "permission"): "com.example.perm.USE",
            ("com.example.DeepLinkActivity", "exported"): "true",
            ("com.example.Files", "exported"): "true",
            ("com.example.Files", "readPermission"): "com.example.perm.READ",
        }

    def get_activities(self) -> list[str]:
        return [
            "com.example.MainActivity",
            "com.example.GuardedActivity",
            "com.example.DeepLinkActivity",
            "com.example.PlainActivity",
        ]

    def get_services(self) -> list[str]:
        return ["com.example.SecretService"]

    def get_receivers(self) -> list[str]:
        return ["com.example.BootReceiver"]

    def get_providers(self) -> list[str]:
        return ["com.example.Files"]

    def get_intent_filters(self, itemtype: str, name: str) -> dict[str, Any]:
        return self._filters.get((itemtype, name), {})

    def get_attribute_value(self, tag: str, attr: str, **kw: Any) -> Any:
        del tag
        return self._attrs.get((kw.get("name"), attr))


def _client() -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    return client


def _payload() -> dict[str, Any]:
    return _client().exported_components(Path("d.apk"))


def test_exported_components_counts_the_whole_surface() -> None:
    payload = _payload()
    # Scanned: 4 activities + 1 service + 1 receiver + 1 provider = 7.
    assert payload["total_components"] == 7
    # Exported: MainActivity, GuardedActivity, DeepLinkActivity (explicit true),
    # BootReceiver (implied by filter), Files (explicit true). SecretService is
    # explicitly false and PlainActivity has neither attribute nor filter.
    assert payload["exported_total"] == 5
    assert payload["count"] == 5
    names = {c["name"] for c in payload["components"]}
    assert "com.example.SecretService" not in names
    assert "com.example.PlainActivity" not in names


def test_exported_components_flag_implied_export() -> None:
    by_name = {c["name"]: c for c in _payload()["components"]}
    boot = by_name["com.example.BootReceiver"]
    # No explicit android:exported, but an intent-filter makes it reachable.
    assert boot["exported"] is None
    assert boot["exported_implied"] is True
    assert boot["has_intent_filter"] is True
    main = by_name["com.example.MainActivity"]
    assert main["exported"] is True
    assert main["exported_implied"] is False


def test_exported_components_report_guards_and_unguarded_count() -> None:
    payload = _payload()
    by_name = {c["name"]: c for c in payload["components"]}
    # MainActivity, DeepLinkActivity and BootReceiver have no permission.
    assert payload["unguarded_count"] == 3
    assert by_name["com.example.GuardedActivity"]["guarded"] is True
    assert by_name["com.example.GuardedActivity"]["permission"] == "com.example.perm.USE"
    files = by_name["com.example.Files"]
    assert files["type"] == "provider"
    assert files["guarded"] is True
    assert files["read_permission"] == "com.example.perm.READ"
    assert by_name["com.example.MainActivity"]["guarded"] is False


def test_exported_components_flag_launcher_and_deep_link() -> None:
    by_name = {c["name"]: c for c in _payload()["components"]}
    assert by_name["com.example.MainActivity"]["launcher"] is True
    deep = by_name["com.example.DeepLinkActivity"]
    assert deep["deep_link"] is True
    assert deep["schemes"] == ["myapp"]
    assert by_name["com.example.MainActivity"]["deep_link"] is False


def test_apk_exported_components_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.exported_components")
    assert "unguarded_count" in doc
    assert "exported_implied" in doc
    assert "effective_exported" in doc
    assert "provider" in doc
