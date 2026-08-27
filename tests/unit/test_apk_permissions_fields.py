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


def test_apk_permissions_says_which_list_the_cap_hit() -> None:
    """A combined has_more cannot say declared vs requested was truncated.

    Both lists are capped independently, but the reply carried one has_more.
    With 300 declared permissions and one requested, has_more is True purely
    because of the declared list -- yet a caller checking the requested set
    could not tell it was complete rather than a short list hidden behind the
    same flag. The per-list flags name the truncated one.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.permissions(Path("dummy.apk"))

    assert payload["has_more"] is True
    assert payload["permissions_truncated"] is True
    assert payload["requested_permissions_truncated"] is False
    assert payload["has_more"] == (
        payload["permissions_truncated"] or payload["requested_permissions_truncated"]
    )
    doc = _tool_docstring("apk.permissions")
    assert "permissions_truncated" in doc
    assert "requested_permissions_truncated" in doc
