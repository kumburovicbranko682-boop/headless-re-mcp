"""An embedded live proxy must not carry mitmdump's file-replay addons.

``keepserving`` and ``readfile``/``readfilestdin`` exist to serve
``mitmdump -r <file>`` and to keep that process alive afterwards; both read
``ctx.options.rfile`` in their ``running()`` hook. Running one master per
session means several masters run in several threads at once, and mitmproxy is
not built for that: ``ctx.options`` then intermittently resolves to a bare
default Options without ``rfile``, the addon raises "No such option: rfile", and
``errorcheck`` escalates it to SystemExit(1) -- a healthy capture dying at
startup about one start in six. We never replay from a file, so
``_drop_cli_only_addons`` removes exactly those readers.

These pin the contract with fakes so they run without mitmproxy installed; the
live ``test_proxy_lifecycle_gate`` proves the same thing against real masters.
"""

from __future__ import annotations

import inspect
from typing import Any

from headless_re_mcp.backends.proxy import client as proxy_client
from headless_re_mcp.backends.proxy.client import _CLI_ONLY_ADDONS, _drop_cli_only_addons


class _FakeAddon:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeAddons:
    """Mimics mitmproxy's AddonManager get/remove by registered name."""

    def __init__(self, names: list[str]) -> None:
        self._by_name = {name: _FakeAddon(name) for name in names}

    def get(self, name: str) -> Any:
        return self._by_name.get(name)

    def remove(self, addon: Any) -> None:
        # mitmproxy raises if the addon is not registered; mirror that so a
        # double-remove or a bad handle would be caught, not silently ignored.
        if addon.name not in self._by_name:
            raise KeyError(addon.name)
        del self._by_name[addon.name]

    def names(self) -> set[str]:
        return set(self._by_name)


class _FakeMaster:
    def __init__(self, names: list[str]) -> None:
        self.addons = _FakeAddons(names)


def test_every_rfile_reading_addon_is_removed() -> None:
    master = _FakeMaster(["core", "proxyserver", "keepserving", "readfilestdin", "errorcheck"])
    _drop_cli_only_addons(master)
    remaining = master.addons.names()
    assert remaining == {"core", "proxyserver", "errorcheck"}
    assert not (remaining & set(_CLI_ONLY_ADDONS))


def test_the_capture_path_addons_are_left_intact() -> None:
    """Only the file-replay addons go; proxyserver/errorcheck must survive."""
    master = _FakeMaster(["proxyserver", "errorcheck", "save", "readfile"])
    _drop_cli_only_addons(master)
    assert master.addons.names() == {"proxyserver", "errorcheck", "save"}


def test_absent_addons_are_a_no_op() -> None:
    """A mitmproxy build without these addons must not raise."""
    master = _FakeMaster(["core", "proxyserver"])
    _drop_cli_only_addons(master)
    assert master.addons.names() == {"core", "proxyserver"}


def test_run_drops_cli_addons_before_starting_the_master() -> None:
    """Guard against a refactor that drops the mitigation or reorders it.

    The addons must be removed before ``master.run()`` is reached, or their
    ``running()`` hook fires and the race is back.
    """
    source = inspect.getsource(proxy_client._ProxyInstance._run)
    assert "_drop_cli_only_addons(" in source
    drop_call = source.index("_drop_cli_only_addons(")
    run_call = source.index("master.run()")
    assert drop_call < run_call
