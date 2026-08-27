"""``device.current_activity`` preserves structured errors, wraps the rest, and gates on package.

Reading the foreground activity goes through ``adbutils.app_current`` and then a
deliberate three-way judgement::

    try:
        current = _call(dev.app_current, timeout=_ADB_SHELL_TIMEOUT_S);
    except AdbError:
        raise                                       # structured failure -> pass through
    except Exception as exc:
        raise AdbError("backend_error", f"failed to read current activity: {exc}") ...;
    package  = getattr(current, "package",  None) if current is not None else None;
    activity = getattr(current, "activity", None) if current is not None else None;
    if not package:                                  # None *or* empty string
        raise AdbError("backend_error", "failed to read current activity", ...);
    return {"package": package, "activity": activity};

The existing ``current_activity`` tests cover exactly two points: the happy path
(package and activity both present) and ``app_current`` returning ``None`` (the
guard fires). Neither touches the ``except`` split or the shape of the guard, so
four behaviours are unpinned:

* **A structured ``AdbError`` from the read passes through unchanged.** ``_device``
  or ``_call`` can raise an ``AdbError`` -- ``capability_unavailable`` on a device
  with no ``dumpsys``, say. The dedicated ``except AdbError: raise`` keeps its code
  and message; flatten it into the generic handler and a precise, non-retryable
  condition becomes an indistinguishable ``backend_error``.

* **A generic exception is wrapped and *names the cause*.** When ``app_current``
  throws something unstructured, the reply is a ``backend_error`` whose message
  ends with ``": <exc>"`` -- distinct from the guard's bare "failed to read current
  activity". A caller can tell "the read threw" from "the read returned nothing".

* **Only ``package`` gates success; ``activity`` may be ``None``.** A foreground app
  can be reported with a package but no resolved activity; that is still a
  successful read (``{package, activity: None}``), not a failure. Gate on activity
  too and legitimate foregrounds start failing.

* **An empty-string package is refused like ``None``.** ``if not package`` catches
  ``""`` as well as ``None`` -- a blank package is a failed read, not a real
  foreground named "". The existing None test cannot show that ``""`` is covered.

These drive ``AdbBackend.current_activity`` with fake devices -- no adbutils, no
emulator.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


def _backend(dev: object) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


class _RaisingCurrent:
    """A device whose ``app_current`` raises a chosen exception."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def app_current(self, timeout: float | None = None) -> Any:
        del timeout
        raise self._exc


class _Current:
    def __init__(self, package: str | None, activity: str | None) -> None:
        self.package = package
        self.activity = activity


class _FixedCurrent:
    """A device returning a fixed ``app_current`` object."""

    def __init__(self, current: _Current) -> None:
        self._current = current

    def app_current(self, timeout: float | None = None) -> _Current:
        del timeout
        return self._current


def test_a_structured_adberror_from_the_read_passes_through_unchanged() -> None:
    """An AdbError from the read keeps its own code, not flattened to backend_error.

    ``capability_unavailable`` (no dumpsys) is a distinct, non-retryable condition;
    the dedicated ``except AdbError: raise`` must preserve it so a caller does not
    treat it like a generic transient read failure.
    """
    device = _RaisingCurrent(AdbError("capability_unavailable", "no dumpsys on this device"))
    with pytest.raises(AdbError) as caught:
        _backend(device).current_activity("emulator-5554")

    assert caught.value.code == "capability_unavailable"
    assert caught.value.message == "no dumpsys on this device"


def test_a_generic_read_failure_is_wrapped_and_names_the_cause() -> None:
    """A non-AdbError from app_current becomes backend_error naming the exception.

    The wrapped message ends with the exception text, which distinguishes "the
    read threw" from the guard's bare "failed to read current activity" (a read
    that returned nothing).
    """
    device = _RaisingCurrent(RuntimeError("dumpsys died"))
    with pytest.raises(AdbError) as caught:
        _backend(device).current_activity("emulator-5554")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "failed to read current activity: dumpsys died"
    # Distinct from the missing-foreground guard, which has no ": <cause>" suffix.
    assert caught.value.message != "failed to read current activity"


def test_a_package_without_a_resolved_activity_is_still_a_success() -> None:
    """A foreground with a package but no activity is a successful read.

    Only ``package`` gates success; ``activity`` may be ``None``. Gating on
    activity too would fail legitimate foregrounds whose activity did not resolve.
    """
    device = _FixedCurrent(_Current(package="com.example.app", activity=None))
    payload = _backend(device).current_activity("emulator-5554")

    assert payload == {"package": "com.example.app", "activity": None}


def test_an_empty_string_package_is_refused_like_none() -> None:
    """A blank package is a failed read, not a real foreground named "".

    ``if not package`` catches ``""`` as well as ``None``; the reply is the guard's
    bare backend_error, and the empty package is surfaced in the details.
    """
    device = _FixedCurrent(_Current(package="", activity="SomeActivity"))
    with pytest.raises(AdbError) as caught:
        _backend(device).current_activity("emulator-5554")

    assert caught.value.code == "backend_error"
    assert caught.value.message == "failed to read current activity"
    assert caught.value.details.get("package") is None
