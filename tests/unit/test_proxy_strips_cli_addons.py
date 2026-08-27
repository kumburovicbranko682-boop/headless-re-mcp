"""The embedded proxy must drop mitmdump's CLI-only addons before running.

DumpMaster ships errorcheck (which calls ``sys.exit()`` on any error logged at
startup) and readfilestdin / keepserving (which read a ``-r rfile`` and keep the
CLI process alive). Embedded on a worker thread, their cold-start race logged
"Addon error: No such option: rfile" and errorcheck turned that into
``sys.exit(1)`` -- an intermittent startup failure. The live gate proves the
real behaviour but skips wherever mitmproxy is absent, so this drives the strip
helper against a fake addon manager and asserts exactly the CLI addons are
removed while the proxy server that actually serves traffic is kept.
"""

from __future__ import annotations

from types import SimpleNamespace

from headless_re_mcp.backends.proxy.client import _strip_cli_only_addons


class _FakeAddons:
    def __init__(self, names: list[str]) -> None:
        # name -> addon object (identity matters for remove()).
        self._by_name = {name: SimpleNamespace(name=name) for name in names}

    def get(self, name: str) -> object | None:
        return self._by_name.get(name)

    def remove(self, addon: object) -> None:
        for name, existing in list(self._by_name.items()):
            if existing is addon:
                del self._by_name[name]
                return
        raise KeyError("addon not registered")

    @property
    def names(self) -> set[str]:
        return set(self._by_name)


def test_strip_removes_cli_addons_but_keeps_the_proxy_server() -> None:
    addons = _FakeAddons(
        [
            "core",
            "proxyserver",
            "nextlayer",
            "tlsconfig",
            "errorcheck",
            "readfilestdin",
            "keepserving",
        ]
    )
    master = SimpleNamespace(addons=addons)

    _strip_cli_only_addons(master)

    # The CLI-lifecycle addons that break an embedded cold start are gone.
    assert "errorcheck" not in addons.names
    assert "readfilestdin" not in addons.names
    assert "keepserving" not in addons.names
    # Everything that actually serves and inspects traffic is untouched.
    assert {"core", "proxyserver", "nextlayer", "tlsconfig"} <= addons.names


def test_strip_is_a_noop_when_the_cli_addons_are_absent() -> None:
    # A mitmproxy build (or future version) that never registered these must not
    # raise -- the helper only removes what is present.
    addons = _FakeAddons(["core", "proxyserver"])
    master = SimpleNamespace(addons=addons)

    _strip_cli_only_addons(master)

    assert addons.names == {"core", "proxyserver"}


def test_strip_tolerates_a_master_without_addons() -> None:
    _strip_cli_only_addons(SimpleNamespace(addons=None))
    _strip_cli_only_addons(SimpleNamespace())
