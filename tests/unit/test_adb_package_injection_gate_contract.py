"""No adb method shells a package name before validating it.

Every adb capability is a named, argument-checked call precisely so a package
name can never smuggle extra arguments into a device shell (the module says so at
the top, and there is deliberately no raw-shell tool). The single invariant that
makes that true is: each public method that accepts a ``package`` runs it through
``_check_package`` -- which admits only ``[A-Za-z0-9_.]`` in dotted form, no shell
metacharacter -- before the package reaches ``dev.shell`` / ``dev.uninstall``. A
method that touched the device before that check, or a new package-taking method
added without it, is a device-side shell injection: ``force_stop(serial,
"com.x; rm -rf /sdcard")`` would run the tail on the device.

``_check_package`` itself is unit-tested against hostile input, but nothing pinned
that the *public entry points* all call it before any device I/O, or that a newly
added one joins the contract -- the same family-level blind spot the frida
pid-gate audit found. This test is self-auditing: it discovers every public method
that declares a ``package`` parameter and fails if the tested set does not cover it
exactly. Then it drives each with a hostile package through a device whose every
method raises, so a package that slipped past the guard surfaces as that
BaseException (device was reached) rather than ``invalid_params`` -- which is what
makes this catch a dropped or reordered guard instead of passing vacuously.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

_HOSTILE = "com.evil.app; rm -rf /sdcard"
_SERIAL = "emulator-5554"


class _DeviceReached(BaseException):
    """Raised if any device method is touched.

    A BaseException so it slips past the clients' ``except Exception`` guards and
    propagates to the test, proving a hostile package reached the device rather
    than being caught and remapped to some other AdbError code.
    """


class _TripwireDevice:
    """A device stand-in whose every attribute is a call that raises."""

    def __getattr__(self, name: str) -> Callable[..., Any]:
        def _trip(*args: Any, **kwargs: Any) -> Any:
            raise _DeviceReached(f"device.{name} reached with args={args!r}")

        return _trip


# name -> a call supplying a package a device shell must never see.
_DENIED_CALLS: dict[str, Callable[[AdbBackend], Any]] = {
    "uninstall": lambda b: b.uninstall(_SERIAL, _HOSTILE),
    "launch": lambda b: b.launch(_SERIAL, _HOSTILE),
    "force_stop": lambda b: b.force_stop(_SERIAL, _HOSTILE),
}


def _package_methods() -> set[str]:
    """Every public method that declares a ``package`` parameter."""
    gated: set[str] = set()
    for name, member in inspect.getmembers(AdbBackend, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        if "package" in inspect.signature(member).parameters:
            gated.add(name)
    return gated


def _armed_backend() -> AdbBackend:
    """A backend whose device resolves to the tripwire without any real adb.

    ``_device`` is stubbed so serial resolution never runs (serials are validated
    and tested separately) and so the only way to reach the device is through the
    package-taking method under test -- which must refuse first.
    """
    backend = AdbBackend()
    backend._device = lambda serial: _TripwireDevice()  # type: ignore[method-assign]
    return backend


def test_the_contract_covers_every_public_package_method() -> None:
    """A new package-taking method must be added to _DENIED_CALLS, or this fails."""
    assert _package_methods() == set(_DENIED_CALLS)


@pytest.mark.parametrize("name", sorted(_DENIED_CALLS))
def test_a_hostile_package_is_refused_before_any_device_shell(name: str) -> None:
    backend = _armed_backend()
    with pytest.raises(AdbError) as caught:
        _DENIED_CALLS[name](backend)
    assert caught.value.code == "invalid_params"
