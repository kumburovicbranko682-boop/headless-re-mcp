"""``apk.permissions`` merges two androguard lists, and either one can overflow.

The reply is built from *two independent* androguard calls, not one::

    declared, declared_more = _cap_names(apk.get_permissions(), _MAX_PERMISSIONS);
    try:
        requested, requested_more = _cap_names(
            apk.get_requested_permissions(), _MAX_PERMISSIONS
        );
    except Exception:                       # older androguard lacks this call
        requested, requested_more = declared, declared_more;
    return {
        "permissions": declared,
        "requested_permissions": requested,
        "count": len(declared),
        "has_more": declared_more or requested_more,
    };

``get_permissions()`` is the *used*/declared set and ``get_requested_permissions()``
is the full manifest ``<uses-permission>`` set -- routinely different sizes -- and
``has_more`` is the OR of *both* caps so a caller learns the reply is partial no
matter which list ran long.

The existing ``permissions`` test feeds a fixture that caps only the *declared*
side (300 permissions -> 256, ``declared_more=True``) while requested is a single
``["R"]``. That pins ``count == len(declared)`` and that declared truncation sets
``has_more`` -- but it leaves two things a one-sided fixture cannot show:

* **The requested cap contributes to ``has_more`` on its own.** With
  ``declared_more`` already True in the existing fixture, ``has_more`` is True
  regardless of the requested side, so dropping ``or requested_more`` stays green
  there. The real case is the mirror image: a handful of *declared* permissions
  but a manifest that requests hundreds. Then ``declared_more`` is False and only
  ``requested_more`` can raise the flag -- and it must, or a caller reads a
  truncated requested list as the whole manifest. ``count`` still counts the
  small declared set, and the two lists stay distinct.

* **A missing ``get_requested_permissions`` falls back to declared, not to empty.**
  Older androguard builds lack the call; the ``except`` aliases requested to the
  declared list (and its cap flag) rather than letting the AttributeError escape
  or returning ``[]``. Drop the fallback and every APK parsed by an older
  androguard either errors out or reports "no requested permissions" -- a silent
  under-report of exactly the manifest facts this tool exists to surface.

These drive ``ApkClient.permissions`` through a fake APK -- no androguard, no DEX.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import _MAX_PERMISSIONS, ApkClient


class _RequestedOverflowApk:
    """A manifest that *declares* few permissions but *requests* far more.

    The declared list is short enough to pass the cap untouched; the requested
    list runs past ``_MAX_PERMISSIONS``. This is the mirror of the existing
    fixture, so the requested side is the only thing that can set ``has_more``.
    """

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.CAMERA"]

    def get_requested_permissions(self) -> list[str]:
        return [f"android.permission.R{index:03d}" for index in range(_MAX_PERMISSIONS + 40)]


class _OlderAndroguardApk:
    """An androguard build without ``get_requested_permissions`` (it raises)."""

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.WAKE_LOCK"]

    def get_requested_permissions(self) -> list[str]:
        raise AttributeError("get_requested_permissions is unavailable in this androguard")


def _client(apk: object) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def test_the_requested_cap_alone_can_raise_has_more() -> None:
    """A large requested set flags the reply partial even when declared is tiny.

    ``declared_more`` is False (two declared permissions, well under the cap), so
    only ``requested_more`` can set ``has_more``. It must -- otherwise a caller
    reads a requested list clipped at the cap as the manifest's complete set.
    """
    payload = _client(_RequestedOverflowApk()).permissions(Path("app.apk"))

    assert payload["has_more"] is True
    assert len(payload["requested_permissions"]) == _MAX_PERMISSIONS
    # count and the declared list stay the small declared side, not the requested one.
    assert payload["count"] == 2
    assert len(payload["permissions"]) == 2
    assert payload["permissions"] == [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]


def test_the_two_lists_stay_distinct_when_only_requested_overflows() -> None:
    """The declared and requested sets are different lists, not one echoed twice.

    A fixture where both sides match cannot tell ``permissions`` from
    ``requested_permissions``; here declared is two entries and requested is the
    capped hundreds, so confusing the two is visible.
    """
    payload = _client(_RequestedOverflowApk()).permissions(Path("app.apk"))

    assert payload["permissions"] != payload["requested_permissions"]
    assert len(payload["permissions"]) == 2
    assert len(payload["requested_permissions"]) == _MAX_PERMISSIONS


def test_a_missing_requested_call_falls_back_to_the_declared_list() -> None:
    """Older androguard lacks the call; requested aliases declared, not empty.

    The ``except`` must neither let the AttributeError escape nor substitute an
    empty list: it copies the declared permissions (and their cap flag) so the
    reply still carries the manifest facts the caller asked for.
    """
    payload = _client(_OlderAndroguardApk()).permissions(Path("app.apk"))

    assert payload["requested_permissions"] == payload["permissions"]
    assert payload["requested_permissions"] == [
        "android.permission.INTERNET",
        "android.permission.WAKE_LOCK",
    ]
    assert payload["count"] == 2
    # Neither list overflowed, so the reply is complete.
    assert payload["has_more"] is False


def test_the_fallback_copies_the_declared_cap_flag_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the declared list overflows and requested is missing, has_more stays True.

    The fallback aliases *both* the list and its ``_more`` flag, so a truncated
    declared set on an older androguard is still reported partial rather than
    losing the flag along with the missing requested call.
    """
    monkeypatch.setattr(apk_client, "_MAX_PERMISSIONS", 4)

    class _OverflowNoRequested:
        def get_permissions(self) -> list[str]:
            return [f"android.permission.P{index}" for index in range(10)]

        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("unavailable")

    payload = _client(_OverflowNoRequested()).permissions(Path("app.apk"))

    assert payload["count"] == 4
    assert len(payload["permissions"]) == 4
    assert payload["requested_permissions"] == payload["permissions"]
    assert payload["has_more"] is True
