"""AdbBackend forward-slot bookkeeping must not leak or forget a forward.

``adb forward`` lives on the adb server, not in this process, so the backend
tracks every ``(serial, local)`` it created in order to tear them down later and
to refuse binding more than ``_MAX_FORWARDS`` at once. The spec validation is
covered elsewhere; what is pinned here is the state around it:

* a failed ``dev.forward`` must not leave the reserved slot behind (that leak
  used to pin the slot until the cap locked the process out),
* re-forwarding the same endpoint must not double-count the slot,
* the cap is enforced,
* ``release_forwards`` reports what it removed and, when a removal fails or the
  device offers no remove API, keeps the slot for the next attempt rather than
  forgetting a forward adb still holds.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import _MAX_FORWARDS, AdbBackend, AdbError


class _ForwardDev:
    """A device that records forwards/removes and can be told to fail."""

    def __init__(self, *, forward_fails: bool = False, remove_fails: bool = False) -> None:
        self._forward_fails = forward_fails
        self._remove_fails = remove_fails
        self.forwarded: list[tuple[str, str]] = []
        self.removed: list[str] = []

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        if self._forward_fails:
            raise RuntimeError("adb refused the bind")
        self.forwarded.append((local, remote))

    def forward_remove(self, local: str, timeout: float | None = None) -> None:
        del timeout
        if self._remove_fails:
            raise RuntimeError("device offline")
        self.removed.append(local)


class _NoRemoverDev:
    """A device that can forward but exposes no forward-remove API."""

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout


def _backend_returning(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def test_a_successful_forward_tracks_exactly_one_slot() -> None:
    dev = _ForwardDev()
    backend = _backend_returning(dev)
    result = backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert result == {"local": "tcp:5000", "remote": "tcp:27042"}
    assert backend._forwards == [("emulator-5554", "tcp:5000")]
    assert dev.forwarded == [("tcp:5000", "tcp:27042")]


def test_a_failed_forward_does_not_leak_the_reserved_slot() -> None:
    """The bind failing must release the slot, or the cap slowly locks us out."""
    dev = _ForwardDev(forward_fails=True)
    backend = _backend_returning(dev)
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "backend_error"
    assert backend._forwards == []


def test_reforwarding_the_same_endpoint_does_not_double_count() -> None:
    """A repeat of the same (serial, local) reuses the slot, not a second one."""
    dev = _ForwardDev()
    backend = _backend_returning(dev)
    backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert backend._forwards == [("emulator-5554", "tcp:5000")]
    # The device was asked both times; only the local slot bookkeeping dedupes.
    assert dev.forwarded == [("tcp:5000", "tcp:27042"), ("tcp:5000", "tcp:27042")]


def test_the_forward_cap_is_enforced() -> None:
    """A new endpoint past the cap is refused, and its slot is never taken."""
    dev = _ForwardDev()
    backend = _backend_returning(dev)
    backend._forwards = [("emulator-5554", f"tcp:{6000 + index}") for index in range(_MAX_FORWARDS)]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    assert caught.value.code == "invalid_state"
    assert caught.value.details.get("cap") == _MAX_FORWARDS
    assert caught.value.details.get("held") == _MAX_FORWARDS
    # The rejected endpoint was never bound and never tracked.
    assert dev.forwarded == []
    assert ("emulator-5554", "tcp:5000") not in backend._forwards


def test_reforwarding_at_the_cap_is_allowed_for_a_held_slot() -> None:
    """A key already held is refreshed even at the cap: it takes no new slot."""
    dev = _ForwardDev()
    backend = _backend_returning(dev)
    held = [("emulator-5554", f"tcp:{6000 + index}") for index in range(_MAX_FORWARDS)]
    backend._forwards = list(held)
    # tcp:6000 is already in the set, so this must not trip the cap.
    result = backend.forward("emulator-5554", "tcp:6000", "tcp:27042")
    assert result["local"] == "tcp:6000"
    assert len(backend._forwards) == _MAX_FORWARDS


def test_release_forwards_removes_and_reports_each() -> None:
    dev = _ForwardDev()
    backend = _backend_returning(dev)
    backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    backend.forward("emulator-5554", "tcp:5001", "tcp:27043")
    report = backend.release_forwards()
    assert report["count"] == 2
    assert {entry["local"] for entry in report["removed"]} == {"tcp:5000", "tcp:5001"}
    assert report["failed"] == []
    assert backend._forwards == []
    assert set(dev.removed) == {"tcp:5000", "tcp:5001"}


def test_release_forwards_keeps_a_slot_whose_removal_failed() -> None:
    """A remove that throws is a retry, not a forget: adb still holds it."""
    dev = _ForwardDev(remove_fails=True)
    backend = _backend_returning(dev)
    backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    report = backend.release_forwards()
    assert report["count"] == 0
    assert len(report["failed"]) == 1
    assert report["failed"][0]["local"] == "tcp:5000"
    # The forward is retained so the next release_forwards tries again.
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


def test_release_forwards_retains_a_slot_when_the_device_has_no_remove_api() -> None:
    """A device that cannot remove a forward is a failure to retry, not a drop."""
    dev = _NoRemoverDev()
    backend = _backend_returning(dev)
    backend.forward("emulator-5554", "tcp:5000", "tcp:27042")
    report = backend.release_forwards()
    assert report["count"] == 0
    assert len(report["failed"]) == 1
    assert "forward-remove" in report["failed"][0]["error"]
    assert backend._forwards == [("emulator-5554", "tcp:5000")]


# --- races: the slot set changes under the bind/release while the lock is free --
#
# forward() and release_forwards() both drop _forward_lock while they talk to
# the adb server, so a second thread can add or remove the same (serial, local)
# in between. The membership checks in the error and retry arms exist purely to
# survive that; without them a concurrent change turns into a ValueError from
# list.remove or a duplicated slot. These pin that the checks actually hold.


class _SlotDroppingDev:
    """A device whose forward() clears the tracked slot before it fails.

    That models a concurrent release_forwards() emptying the set during the
    bind, so the error arm meets a key that is no longer present.
    """

    def __init__(self, backend: AdbBackend, error: BaseException) -> None:
        self._backend = backend
        self._error = error

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        self._backend._forwards.clear()
        raise self._error


def test_an_adberror_after_the_slot_was_concurrently_dropped_reraises_cleanly() -> None:
    """The domain-error arm must not choke removing a slot already gone."""
    backend = AdbBackend()
    backend._available = True
    dev = _SlotDroppingDev(backend, AdbError("device_offline", "adb dropped the device"))
    backend._device = lambda serial: dev  # type: ignore[method-assign]

    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")

    # The original AdbError is re-raised untouched, and the missing-key cleanup
    # did not raise a ValueError of its own.
    assert caught.value.code == "device_offline"
    assert backend._forwards == []


def test_a_generic_error_after_the_slot_was_concurrently_dropped_wraps_cleanly() -> None:
    """The catch-all arm has the same guard, ending in a wrapped backend_error."""
    backend = AdbBackend()
    backend._available = True
    dev = _SlotDroppingDev(backend, RuntimeError("usb yanked"))
    backend._device = lambda serial: dev  # type: ignore[method-assign]

    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:5000", "tcp:27042")

    assert caught.value.code == "backend_error"
    assert "usb yanked" in caught.value.message
    assert backend._forwards == []


def test_release_does_not_double_track_a_slot_reforwarded_during_the_sweep() -> None:
    """A slot re-created mid-release is retried once, not appended twice."""
    backend = AdbBackend()
    backend._available = True
    key = ("emulator-5554", "tcp:5000")
    backend._forwards = [key]

    class _ReaddingDev:
        def forward_remove(self, local: str, timeout: float | None = None) -> None:
            del local, timeout
            # Stand in for a concurrent forward() that re-reserved the same slot
            # after release_forwards cleared the set but before it recorded the
            # retry: the retry pass must notice the key is already back.
            if key not in backend._forwards:
                backend._forwards.append(key)
            raise RuntimeError("removal raced a re-forward")

    backend._device = lambda serial: _ReaddingDev()  # type: ignore[method-assign]

    report = backend.release_forwards()

    assert report["failed"][0]["local"] == "tcp:5000"
    assert backend._forwards == [key]
