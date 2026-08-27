"""_frida_server_visible: a host-error ps read is unknown, not "not running".

adbutils hands back the adb host's own "error:" / "adb:" line as stdout rather
than raising, so an offline device answers ``ps`` with a host-error line that of
course does not contain "frida-server". Read naively that is a confident False
for a device we never reached -- and ``ensure_frida_server`` then reports
``running: false`` ("not visible in ps") for a device that simply never
answered. The helper now returns None when *both* ps reads are host-error lines,
matching the honesty guard ``device.properties`` / ``packages`` / ``logcat`` and
``pm path`` already apply, so ensure reports an unverifiable ``running: null``
instead of a definitive False. Absence still means "not running" when at least
one read was a real listing.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import _frida_server_visible


class _FakeDev:
    """A device whose ``shell`` returns canned output for each call in order."""

    def __init__(self, outputs: list[str]) -> None:
        self._outputs = list(outputs)
        self.calls: list[Any] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        self.calls.append(args)
        return self._outputs.pop(0)


def test_returns_true_when_frida_server_in_primary_listing() -> None:
    dev = _FakeDev(["1 init\n2 zygote\n999 frida-server\n"])
    assert _frida_server_visible(dev) is True
    # A hit in `ps -A` short-circuits; the fallback `ps` is not needed.
    assert len(dev.calls) == 1


def test_returns_true_when_only_the_fallback_listing_has_it() -> None:
    dev = _FakeDev(["1 init\n2 zygote\n", "u0_a1 frida-server\n"])
    assert _frida_server_visible(dev) is True


def test_returns_false_when_a_real_listing_lacks_frida_server() -> None:
    dev = _FakeDev(["1 init\n2 zygote\n3 system_server\n", "1 init\n2 zygote\n"])
    assert _frida_server_visible(dev) is False


def test_returns_none_when_both_reads_are_host_errors() -> None:
    # Neither ps ever ran: the device answered both with the adb host's own
    # error line, so absence of "frida-server" proves nothing.
    dev = _FakeDev(["error: device offline\n", "error: device offline\n"])
    assert _frida_server_visible(dev) is None


def test_returns_false_when_only_one_read_is_a_host_error() -> None:
    # The fallback ps was a real listing that did not name frida-server, which
    # is a legitimate "not running" even though the first read errored.
    dev = _FakeDev(["adb: device 'x' not found\n", "1 init\n2 zygote\n"])
    assert _frida_server_visible(dev) is False
