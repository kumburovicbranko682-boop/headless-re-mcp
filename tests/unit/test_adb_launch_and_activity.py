"""device.launch and device.current_activity must verify, never assume, success.

Both ops summarise a device read into a tri-state answer, and neither had a test:

  * launch runs ``monkey`` and then reads the foreground with ``app_current``.
    ``launched`` is True only when the foreground package is the one asked for,
    False when a different app is in front, and null when the foreground could
    not be read at all -- so an agent is never told an app launched on the basis
    that monkey merely returned. A monkey that fails outright is a backend_error.
  * current_activity refuses to pass off an unreadable foreground as an empty
    one: ``app_current`` returning None (a failed dumpsys) used to answer
    ``{package: None}`` as success, which reads as "nothing is in front" rather
    than "the read failed". It now raises backend_error, and a raising
    ``app_current`` is classified the same way instead of leaking raw.

These drive a fake device exposing ``shell`` and ``app_current`` -- no adbutils,
no emulator -- exactly where the verification decisions live.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

_PACKAGE = "com.example.app"
_MISSING = object()


class _AppDev:
    """A device whose monkey shell and app_current can each be scripted.

    ``current`` is what ``app_current`` returns (a namespace with package/
    activity, or None); the *_raises flags make the corresponding call fail the
    way a stalled shell or a broken dumpsys does.
    """

    def __init__(
        self,
        *,
        current: Any = _MISSING,
        shell_raises: bool = False,
        app_current_raises: bool = False,
    ) -> None:
        self._current = current
        self._shell_raises = shell_raises
        self._app_current_raises = app_current_raises
        self.calls: list[Any] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        if self._shell_raises:
            raise RuntimeError("monkey died")
        return ""

    def app_current(self, timeout: float | None = None) -> Any:
        del timeout
        if self._app_current_raises:
            raise RuntimeError("dumpsys failed")
        return self._current


def _backend_with(dev: _AppDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_launch_confirms_the_app_reached_the_foreground() -> None:
    """monkey ran and the foreground is the launched package: launched True."""
    dev = _AppDev(current=SimpleNamespace(package=_PACKAGE, activity=".Main"))
    result = _backend_with(dev).launch("emulator-5554", _PACKAGE)
    assert result == {"launched": True, "package": _PACKAGE, "foreground": _PACKAGE}


def test_launch_reports_not_launched_when_a_different_app_is_in_front() -> None:
    """A foreground that is some other app means the launch did not take.

    monkey returning is not proof: the target may have crashed on start or been
    denied. launched must be False, and the foreground actually seen is reported
    so the caller can tell what happened.
    """
    dev = _AppDev(current=SimpleNamespace(package="com.other.app", activity=".X"))
    result = _backend_with(dev).launch("emulator-5554", _PACKAGE)
    assert result["launched"] is False
    assert result["foreground"] == "com.other.app"


def test_launch_is_null_when_the_foreground_cannot_be_read() -> None:
    """If app_current fails, launched is null with a note -- not a false True.

    monkey ran, but the foreground read failed, so whether the app is up is
    genuinely unknown. The tri-state null keeps that honest rather than guessing.
    """
    dev = _AppDev(app_current_raises=True)
    result = _backend_with(dev).launch("emulator-5554", _PACKAGE)
    assert result["launched"] is None
    assert "could not read foreground" in result["note"]


def test_launch_maps_a_monkey_failure_to_backend_error() -> None:
    """A monkey shell that fails is a backend_error naming the target package.

    _device_shell classifies the shell failure; launch carries the package onto
    that classified error (the context its old dead except-arm meant to add but
    never reached), so an agent sees which app's launch failed without parsing
    the message.
    """
    dev = _AppDev(shell_raises=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).launch("emulator-5554", _PACKAGE)
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("package") == _PACKAGE


def test_force_stop_maps_a_shell_failure_to_backend_error_naming_the_package() -> None:
    """An am force-stop that fails is a backend_error carrying the package.

    Mirrors launch: the failure is classified by _device_shell and the package
    is attached on the way out, so the previously dead generic arm's intent --
    naming the target -- is now actually delivered.
    """
    dev = _AppDev(shell_raises=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).force_stop("emulator-5554", _PACKAGE)
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("package") == _PACKAGE


def test_current_activity_returns_the_package_and_activity() -> None:
    """A readable foreground is reported as its package and activity."""
    dev = _AppDev(current=SimpleNamespace(package=_PACKAGE, activity=".Main"))
    result = _backend_with(dev).current_activity("emulator-5554")
    assert result == {"package": _PACKAGE, "activity": ".Main"}


def test_current_activity_is_a_backend_error_when_the_foreground_is_unreadable() -> None:
    """app_current returning None is a failed read, not an empty foreground.

    Answering {package: None} as success reads as 'nothing is in front', hiding a
    dumpsys that failed. The op raises backend_error so the caller knows the read
    did not produce a foreground rather than that there was none.
    """
    dev = _AppDev(current=None)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"
    assert "failed to read current activity" in caught.value.message


def test_current_activity_classifies_a_raising_app_current() -> None:
    """A raising app_current is the same backend_error, not a leaked exception."""
    dev = _AppDev(app_current_raises=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).current_activity("emulator-5554")
    assert caught.value.code == "backend_error"
    assert "failed to read current activity" in caught.value.message
