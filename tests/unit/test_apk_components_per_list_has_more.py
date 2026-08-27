"""``apk.components`` caps four manifest lists independently and ORs their flags.

The manifest's four component kinds are read, capped, and reported separately,
and ``has_more`` is the OR across all four so *any* overflow tells the caller the
reply is partial::

    activities, a_more = _cap_names(apk.get_activities(), _MAX_COMPONENT_NAMES);
    services,   s_more = _cap_names(apk.get_services(),   _MAX_COMPONENT_NAMES);
    receivers,  r_more = _cap_names(apk.get_receivers(),  _MAX_COMPONENT_NAMES);
    providers,  p_more = _cap_names(apk.get_providers(),  _MAX_COMPONENT_NAMES);
    return {
        "activities": activities, "services": services,
        "receivers": receivers, "providers": providers,
        "main_activity": apk.get_main_activity(),
        "has_more": a_more or s_more or r_more or p_more,
    };

Both existing ``components`` tests (the field-names test and the resource-bounds
test) overflow *only* ``get_activities()`` -- 300 (or cap+10) activities, with
services/receivers/providers each a single entry or empty. So across the whole
suite ``has_more`` is only ever raised by the activities cap, and three things a
one-list fixture cannot show are unpinned:

* **Each of the other three lists raises ``has_more`` on its own.** An APK can
  ship one activity but dozens of broadcast receivers, or a wall of content
  providers. With only ``a_more`` ever True, dropping ``or s_more``, ``or r_more``
  or ``or p_more`` from the OR stays green -- yet each of those overflows must set
  the flag, or a caller reads a clipped receiver/provider/service list as the
  manifest's complete set.

* **A manifest that fits under every cap reports ``has_more`` False.** Both
  existing tests always overflow activities, so ``has_more`` is never observed
  False. Hardcode it True and a small, fully-listed manifest would falsely claim
  it was truncated -- the "complete" signal is untested.

* **Each list lands in its own field.** The four ``_cap_names`` calls read four
  different androguard methods into four different keys; a distinct value per kind
  proves receivers are not services and providers are not activities, which a
  fixture of ``["S"]``/``["R"]``/``["P"]`` singletons only weakly shows and a
  swapped read could still satisfy for the overflow counts alone.

These drive ``ApkClient.components`` through fake APKs -- no androguard, no
manifest -- at the real ``_MAX_COMPONENT_NAMES`` cap, overflowing exactly one
list at a time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import _MAX_COMPONENT_NAMES, ApkClient

_KINDS = ("activities", "services", "receivers", "providers")


class _ComponentsApk:
    """A fake APK whose four component lists are set per-kind for the test.

    ``overflow`` names the single kind that runs past the cap; the other three
    stay a single entry so only the named one can raise ``has_more``.
    """

    def __init__(self, overflow: str | None) -> None:
        self._lists = {
            kind: (
                [f"{kind}{index}" for index in range(_MAX_COMPONENT_NAMES + 5)]
                if kind == overflow
                else [f"{kind}-only"]
            )
            for kind in _KINDS
        }

    def get_activities(self) -> list[str]:
        return self._lists["activities"]

    def get_services(self) -> list[str]:
        return self._lists["services"]

    def get_receivers(self) -> list[str]:
        return self._lists["receivers"]

    def get_providers(self) -> list[str]:
        return self._lists["providers"]

    def get_main_activity(self) -> str:
        return "com.example.Main"


def _client(apk: object) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


@pytest.mark.parametrize("overflow", _KINDS)
def test_each_component_list_raises_has_more_on_its_own(overflow: str) -> None:
    """Whichever single kind overflows, ``has_more`` is True and only it is capped.

    Only ``overflow`` runs past the cap; the other three are single entries. So
    only that kind's ``_more`` flag can set ``has_more`` -- pinning that services,
    receivers and providers each feed the OR, not just activities.
    """
    payload = _client(_ComponentsApk(overflow)).components(Path("app.apk"))

    assert payload["has_more"] is True
    assert len(payload[overflow]) == _MAX_COMPONENT_NAMES
    for other in _KINDS:
        if other != overflow:
            assert payload[other] == [f"{other}-only"]


def test_a_manifest_under_every_cap_is_not_flagged_partial() -> None:
    """No list overflows, so ``has_more`` is False -- the untested "complete" case.

    Both existing tests always overflow activities; none observes the flag False.
    A small manifest that fits under every cap must not claim it was truncated.
    """
    payload = _client(_ComponentsApk(overflow=None)).components(Path("app.apk"))

    assert payload["has_more"] is False
    for kind in _KINDS:
        assert payload[kind] == [f"{kind}-only"]
    assert payload["main_activity"] == "com.example.Main"


def test_each_kind_lands_in_its_own_field() -> None:
    """Four distinct reads route to four distinct keys, not crossed or aliased.

    A distinct value per kind proves receivers are not services and providers are
    not activities -- a swapped ``_cap_names`` read would surface here.
    """

    class _DistinctApk:
        def get_activities(self) -> list[str]:
            return ["com.example.MainActivity", "com.example.SecondActivity"]

        def get_services(self) -> list[str]:
            return ["com.example.SyncService"]

        def get_receivers(self) -> list[str]:
            return ["com.example.BootReceiver"]

        def get_providers(self) -> list[str]:
            return ["com.example.FilesProvider"]

        def get_main_activity(self) -> str:
            return "com.example.MainActivity"

    payload = _client(_DistinctApk()).components(Path("app.apk"))

    assert payload["activities"] == [
        "com.example.MainActivity",
        "com.example.SecondActivity",
    ]
    assert payload["services"] == ["com.example.SyncService"]
    assert payload["receivers"] == ["com.example.BootReceiver"]
    assert payload["providers"] == ["com.example.FilesProvider"]
    assert payload["has_more"] is False
