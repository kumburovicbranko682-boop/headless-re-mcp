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

    def get_details_permissions(self) -> dict[str, list[str]]:
        return {}


class _PermDetailApk:
    """A fake whose permission details drive the dangerous classification."""

    def get_permissions(self) -> list[str]:
        return [
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
            "com.custom.MY_OWN_PERMISSION",
        ]

    def get_requested_permissions(self) -> list[str]:
        return self.get_permissions()

    def get_details_permissions(self) -> dict[str, list[str]]:
        # androguard-shaped: [protectionLevel, label, description]; the base
        # level is the part before any '|' flag. Custom perms are absent.
        return {
            "android.permission.CAMERA": ["dangerous|instant", "take pictures", "..."],
            "android.permission.ACCESS_FINE_LOCATION": ["dangerous", "location", "..."],
            "android.permission.INTERNET": ["normal|instant", "network", "..."],
        }


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
    assert payload["dangerous_permissions"] == []
    assert payload["dangerous_count"] == 0
    doc = _tool_docstring("apk.permissions")
    assert "Answers with permissions" in doc
    assert "requested_permissions" in doc
    assert "has_more" in doc


def test_apk_permissions_flags_dangerous_requested_permissions() -> None:
    """dangerous_permissions is the requested subset whose base protection
    level is 'dangerous', flags after '|' ignored; normal and custom
    (unclassified) permissions stay out, and the list is sorted.
    """
    client = ApkClient()
    client._apk = lambda _path: _PermDetailApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))
    assert payload["dangerous_permissions"] == [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
    ]
    assert payload["dangerous_count"] == 2
    assert "android.permission.INTERNET" not in payload["dangerous_permissions"]
    assert "com.custom.MY_OWN_PERMISSION" not in payload["dangerous_permissions"]
    doc = _tool_docstring("apk.permissions")
    assert "dangerous_permissions" in doc
    assert "dangerous_count" in doc


def test_apk_permissions_survives_missing_or_malformed_details() -> None:
    """An androguard without get_details_permissions, or one returning junk,
    yields an empty dangerous list rather than an error."""

    class _NoDetails:
        def get_permissions(self) -> list[str]:
            return ["android.permission.CAMERA"]

        def get_requested_permissions(self) -> list[str]:
            return ["android.permission.CAMERA"]

    class _JunkDetails(_NoDetails):
        def get_details_permissions(self) -> dict[str, object]:
            return {"android.permission.CAMERA": None, "x": []}

    client = ApkClient()
    for fake in (_NoDetails(), _JunkDetails()):
        client._apk = lambda _path, _fake=fake: _fake  # type: ignore[method-assign]
        payload = client.permissions(Path("dummy.apk"))
        assert payload["dangerous_permissions"] == []
        assert payload["dangerous_count"] == 0
