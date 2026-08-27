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
    # A parser without the declared-permissions accessor degrades cleanly.
    assert payload["declared_permissions"] == []
    doc = _tool_docstring("apk.permissions")
    assert "Answers with permissions" in doc
    assert "requested_permissions" in doc
    assert "has_more" in doc


class _CustomPermApk:
    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_declared_permissions_details(self) -> dict[str, dict[str, str]]:
        return {
            "com.app.C2D_MESSAGE": {"protectionLevel": "signature", "label": "l"},
            "com.app.WEAK": {"protectionLevel": "normal"},
        }


def test_apk_permissions_surfaces_app_declared_permissions_with_levels() -> None:
    """The app's own <permission> definitions and their protection level are a
    privilege boundary; a normal level guarding IPC is a finding.

    Measured: two declared permissions returned as {name, protection_level},
    sorted by name, distinct from the uses-permission lists.
    """
    client = ApkClient()
    client._apk = lambda _path: _CustomPermApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert payload["declared_permissions"] == [
        {"name": "com.app.C2D_MESSAGE", "protection_level": "signature"},
        {"name": "com.app.WEAK", "protection_level": "normal"},
    ]
    # Declared permissions are separate from the requested/used view.
    assert payload["requested_permissions"] == ["android.permission.INTERNET"]
    doc = _tool_docstring("apk.permissions")
    assert "declared_permissions" in doc
    assert "protection_level" in doc
