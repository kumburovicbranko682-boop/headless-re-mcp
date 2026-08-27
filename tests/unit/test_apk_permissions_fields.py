"""apk.permissions must report the two permission sets androguard actually has.

androguard's ``APK`` has ``get_permissions()`` (the ``<uses-permission>`` set the
app requests) and ``get_declared_permissions()`` (the app's own ``<permission>``
definitions). It has *no* ``get_requested_permissions()``. The old code called
that nonexistent getter, caught the ``AttributeError``, and echoed the requested
list under a ``requested_permissions`` field -- a duplicate that also hid the
genuinely distinct declared set. The earlier unit fake papered over this by
implementing ``get_requested_permissions``, a method the real library never had.

These fakes mirror the real API so the contract is pinned against reality.
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
    """Mirror androguard's real APK permission surface for the test.

    Deliberately exposes get_permissions and get_declared_permissions and NOT
    get_requested_permissions -- exactly what androguard 4.x offers.
    """

    def __init__(self, requested: list[str], declared: list[str]) -> None:
        self._requested = requested
        self._declared = declared

    def get_permissions(self) -> list[str]:
        return self._requested

    def get_declared_permissions(self) -> list[str]:
        return self._declared


class _OldFakeApk:
    """An older androguard without get_declared_permissions."""

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET"]


def _permissions(apk: Any) -> dict[str, Any]:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client.permissions(Path("dummy.apk"))


def test_requested_and_declared_are_reported_as_distinct_sets() -> None:
    payload = _permissions(
        _FakeApk(
            requested=["android.permission.INTERNET"],
            declared=["com.example.permgate.CUSTOM_ACCESS"],
        )
    )
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["declared_permissions"] == ["com.example.permgate.CUSTOM_ACCESS"]
    assert payload["count"] == 1
    assert payload["declared_count"] == 1
    assert payload["has_more"] is False
    # The broken alias is gone: no field that merely echoes permissions.
    assert "requested_permissions" not in payload


def test_permissions_cap_applies_to_requested_set() -> None:
    """300 requested, cap 256 -> count 256 and has_more, not a whole manifest."""
    payload = _permissions(_FakeApk(requested=[f"P{index}" for index in range(300)], declared=[]))
    assert payload["count"] == 256
    assert len(payload["permissions"]) == 256
    assert payload["has_more"] is True
    assert payload["declared_permissions"] == []
    assert payload["declared_count"] == 0


def test_missing_declared_getter_yields_empty_not_error() -> None:
    """An older androguard lacking get_declared_permissions must not crash."""
    payload = _permissions(_OldFakeApk())
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["declared_permissions"] == []
    assert payload["declared_count"] == 0
    assert payload["has_more"] is False


def test_docstring_names_the_returned_fields() -> None:
    doc = _tool_docstring("apk.permissions")
    flat = " ".join(doc.split())
    assert "Answers with permissions" in flat
    assert "declared_permissions" in flat
    assert "declared_count" in flat
    assert "has_more" in flat
    # It must not promise a requested_permissions field that no longer exists.
    assert "no requested_permissions field" in flat
