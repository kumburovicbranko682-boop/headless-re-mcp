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
    doc = _tool_docstring("apk.permissions")
    assert "Answers with permissions" in doc
    assert "requested_permissions" in doc
    assert "has_more" in doc


class _DefiningApk:
    """An app that defines its own <permission> elements (and requests one)."""

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_declared_permissions(self) -> list[str]:
        return ["com.example.perm.B", "com.example.perm.A"]


class _ManyDefinedApk:
    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_requested_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]

    def get_declared_permissions(self) -> list[str]:
        return [f"com.example.perm.{index:03d}" for index in range(300)]


def test_apk_permissions_lists_the_apps_own_permission_definitions() -> None:
    """declared_permissions carries the <permission> elements the app defines.

    get_permissions is the manifest's uses-permission request list; the
    custom permissions an app defines to guard its exported components were
    not exposed at all, so a triage that asked this tool could not see them.
    They come back sorted like every other name list.
    """
    client = ApkClient()
    client._apk = lambda _path: _DefiningApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert payload["declared_permissions"] == [
        "com.example.perm.A",
        "com.example.perm.B",
    ]
    assert payload["has_more"] is False
    doc = _tool_docstring("apk.permissions")
    assert "declared_permissions" in doc


def test_apk_permissions_folds_a_capped_declared_list_into_has_more() -> None:
    """300 definitions, cap 256 -> the capped list still trips has_more."""
    client = ApkClient()
    client._apk = lambda _path: _ManyDefinedApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert len(payload["declared_permissions"]) == 256
    assert payload["has_more"] is True


def test_apk_permissions_omits_declared_when_androguard_cannot_enumerate() -> None:
    """Absence means could-not-read, never none-defined.

    _FakeApk has no get_declared_permissions, standing in for an androguard
    without it: the field must be omitted rather than returned as an empty
    list an analyst would read as "no custom permissions defined".
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert "declared_permissions" not in payload
