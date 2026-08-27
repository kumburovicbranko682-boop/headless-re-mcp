"""apk.permissions descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
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
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign, assignment]
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


class _FakeApkLists:
    def __init__(self, declared: list[str], requested: list[str]) -> None:
        self._declared = declared
        self._requested = requested

    def get_permissions(self) -> list[str]:
        return self._declared

    def get_requested_permissions(self) -> list[str]:
        return self._requested


def _permissions_over(declared: list[str], requested: list[str]) -> dict[str, Any]:
    client = ApkClient()
    client._apk = lambda _path: _FakeApkLists(declared, requested)  # type: ignore[method-assign, assignment]
    return client.permissions(Path("dummy.apk"))


def test_count_is_the_declared_list_and_requested_count_is_the_requested_list() -> None:
    """The common app defines no permissions but requests many.

    get_permissions returns the custom permissions the app declares -- almost
    always none -- while get_requested_permissions returns what it asks for.
    count is len(permissions), so it reads 0 for that app; without
    requested_count a caller keying off count concludes "no permissions" while
    the requested list holds several. requested_count exposes that list's size
    directly instead of forcing an inference from len(requested_permissions).
    """
    payload = _permissions_over(
        [], ["android.permission.INTERNET", "android.permission.CAMERA"]
    )
    assert payload["count"] == 0
    assert payload["requested_count"] == 2
    assert payload["permissions"] == []
    assert len(payload["requested_permissions"]) == 2
    assert payload["has_more"] is False
    assert payload["permissions_has_more"] is False
    assert payload["requested_permissions_has_more"] is False


def test_per_list_has_more_flags_the_requested_list_when_it_overflows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """has_more is the OR of both lists; the per-list flags disambiguate it.

    Cap the lists low, then overflow only the requested list. The combined
    has_more was all a caller got, so it could not tell the complete
    permissions list from the truncated requested one -- the very thing the
    docstring promised it could. requested_permissions_has_more must be True
    while permissions_has_more stays False.
    """
    monkeypatch.setattr(apk_client, "_MAX_PERMISSIONS", 2)
    payload = _permissions_over(["p.A"], ["r.A", "r.B", "r.C"])
    assert payload["permissions_has_more"] is False
    assert payload["requested_permissions_has_more"] is True
    assert payload["has_more"] is True
    assert payload["count"] == 1
    assert payload["requested_count"] == 2


def test_per_list_has_more_flags_the_declared_list_when_it_overflows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror image: overflow only the declared list.

    Proves the flags track their own list rather than both reflecting the
    combined has_more.
    """
    monkeypatch.setattr(apk_client, "_MAX_PERMISSIONS", 2)
    payload = _permissions_over(["p.A", "p.B", "p.C"], ["r.A"])
    assert payload["permissions_has_more"] is True
    assert payload["requested_permissions_has_more"] is False
    assert payload["has_more"] is True
