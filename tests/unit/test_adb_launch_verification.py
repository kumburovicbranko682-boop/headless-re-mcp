"""device.launch must verify the app actually reached the foreground.

force_stop, install and uninstall all carry a tri-state result (true / false /
null) and are pinned; launch has the same shape and no test at all. monkey
returning is not proof the app launched -- it can bounce off a crash, a
permission dialog, or simply not come to the front -- so launch reads
``app_current`` back and reports:

  * ``launched=True``  only when the foreground package is the one asked for,
  * ``launched=False`` when the foreground is a different app or unreadable,
  * ``launched=None``  when the foreground read itself failed (could not verify),

alongside the ``foreground`` package it actually saw. Without a test, an
inverted or hardcoded comparison, or a swallowed verification error collapsing
to a guess, would let an agent read "monkey ran" as "app is up".
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _Current:
    def __init__(self, package: str | None) -> None:
        self.package = package


class _LaunchDev:
    """A device that runs the monkey shell and answers app_current for the
    verification read. ``current`` is returned by app_current unless
    ``current_raises`` is set; ``shell_raises`` fails the monkey command."""

    def __init__(
        self,
        current: _Current | None,
        *,
        shell_raises: bool = False,
        current_raises: bool = False,
    ) -> None:
        self._current = current
        self._shell_raises = shell_raises
        self._current_raises = current_raises
        self.calls: list[Any] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        if self._shell_raises:
            raise RuntimeError("monkey exploded")
        return "Events injected: 1"

    def app_current(self, timeout: float | None = None) -> _Current:
        del timeout
        if self._current_raises:
            raise RuntimeError("dumpsys unavailable")
        assert self._current is not None
        return self._current


def _backend_with(dev: _LaunchDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_launch_confirms_the_app_that_reached_the_foreground() -> None:
    """foreground package == the one asked for -> launched True, and the
    foreground it saw is echoed."""
    dev = _LaunchDev(_Current("com.example.app"))
    payload = _backend_with(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is True
    assert payload["package"] == "com.example.app"
    assert payload["foreground"] == "com.example.app"


def test_a_different_foreground_is_not_a_successful_launch() -> None:
    """monkey ran but another app is in front (a launch that bounced): launched
    False, and foreground names what actually won -- not the requested package.
    """
    dev = _LaunchDev(_Current("com.other.app"))
    payload = _backend_with(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is False
    assert payload["foreground"] == "com.other.app"


def test_an_unreadable_foreground_package_is_false_not_null() -> None:
    """app_current answered but with no package (foreground None). That is a
    definite "not in front", so launched is False with foreground None -- the
    null tri-state is reserved for a verification that could not run at all.
    """
    dev = _LaunchDev(_Current(None))
    payload = _backend_with(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is False
    assert payload["foreground"] is None


def test_a_foreground_read_that_fails_leaves_launched_null_not_a_guess() -> None:
    """When app_current raises, launch cannot know whether the app came up, so
    launched stays null with a note -- it must not collapse to True or False.
    """
    dev = _LaunchDev(None, current_raises=True)
    payload = _backend_with(dev).launch("emulator-5554", "com.example.app")
    assert payload["launched"] is None
    assert payload["package"] == "com.example.app"
    assert "foreground" not in payload
    assert "could not read foreground" in payload["note"]


def test_launch_rejects_a_bad_package_before_touching_the_device() -> None:
    """An illegal package id is refused as invalid_params, and the monkey
    command is never sent to the device."""
    dev = _LaunchDev(_Current("com.example.app"))
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).launch("emulator-5554", "not a package!!")
    assert caught.value.code == "invalid_params"
    assert dev.calls == []


def test_a_monkey_that_fails_is_a_backend_error() -> None:
    """A launch command that raises on the device is a backend_error, not a
    silent launched-false."""
    dev = _LaunchDev(_Current("com.example.app"), shell_raises=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).launch("emulator-5554", "com.example.app")
    assert caught.value.code == "backend_error"
