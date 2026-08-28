"""apk.permissions descriptions must name the fields the parser actually returns."""

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
    def get_permissions(self) -> list[str]:
        return [f"P{index}" for index in range(300)]

    def get_requested_permissions(self) -> list[str]:
        return ["R"]

    def get_declared_permissions(self) -> list[str]:
        return ["com.example.permission.CUSTOM", "com.example.permission.OTHER"]


class _ModernApk:
    """androguard >= 4: no get_requested_permissions, has declared."""

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.CAMERA"]

    def get_declared_permissions(self) -> list[str]:
        return ["com.example.permission.CUSTOM"]


def test_apk_permissions_names_permissions_not_declared() -> None:
    """The catalog said declared and requested; the parser has no such fields.

    Measured: 300 permissions, cap 256 -> count 256, has_more True, fields
    are permissions and requested_permissions. declared/requested are
    absent. Looking for declared after a successful call reads as no
    permissions, and a full 256 list with no has_more reads as the whole
    manifest.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert "declared" not in payload
    assert "requested" not in payload
    assert payload["count"] == 256
    assert len(payload["permissions"]) == 256
    assert payload["has_more"] is True
    assert payload["requested_permissions"] == ["R"]
    doc = _tool_docstring("apk.permissions")
    assert "Answers with permissions" in doc
    assert "requested_permissions" in doc
    assert "has_more" in doc


def test_apk_permissions_surfaces_app_defined_declared_permissions() -> None:
    """apk.permissions must surface get_declared_permissions (the app's own
    <permission> definitions), a list distinct from what the app requests."""
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert payload["declared_permissions"] == [
        "com.example.permission.CUSTOM",
        "com.example.permission.OTHER",
    ]
    assert payload["declared_count"] == 2
    doc = _tool_docstring("apk.permissions")
    assert "declared_permissions" in doc


def test_apk_permissions_on_modern_androguard_without_requested_getter() -> None:
    """When get_requested_permissions is absent (androguard >= 4), the alias
    falls back to get_permissions, and declared is still surfaced."""
    client = ApkClient()
    client._apk = lambda _path: _ModernApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    # _cap_names returns the names sorted.
    assert payload["permissions"] == [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]
    assert payload["requested_permissions"] == payload["permissions"]
    assert payload["declared_permissions"] == ["com.example.permission.CUSTOM"]
    assert payload["count"] == 2
    assert payload["declared_count"] == 1
    assert payload["has_more"] is False
