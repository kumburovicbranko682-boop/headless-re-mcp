"""AdbBackend edge arcs: import success, verify parsing, and error bookkeeping.

These pin the branches the mainline device tests never walk: the adbutils
import actually succeeding, ``pm path`` output with host noise before the
``package:`` line, the ``ps`` fallback meeting a matching row with no PID
column, the property page cap, devices whose ``sync``/``app_current`` surface
is missing or empty, and the ``forward``/``release_forwards`` bookkeeping when
the reservation was never taken or has already been dropped by the time the
error handler runs. Each of these is a caller-visible contract: a forward
failure must not leak (or double-free) a reservation slot, and a launch or
force-stop that dies outside adb's own error shape must still come back as a
structured AdbError rather than a raw exception.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.adb.client as adapter
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

_SERIAL = "emulator-5554"


class _ScriptedShell:
    """A device whose ``shell`` answers by the command's leading tokens."""

    def __init__(self, responses: dict[tuple[str, ...], str]) -> None:
        self._responses = responses
        self.calls: list[list[str] | str] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.calls.append(args)
        tokens = tuple(args) if isinstance(args, list) else tuple(str(args).split())
        for matcher, output in self._responses.items():
            if tokens[: len(matcher)] == matcher:
                return output
        return ""


def _backend_with(dev: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


# ---------------------------------------------------------------------------
# Module helpers.


def test_device_info_row_reads_a_single_element_tuple() -> None:
    """A bare (serial,) row keeps the serial and reports state unknown.

    Older adbutils listings can be one-element tuples; indexing past the end
    for the state would raise where the row should simply degrade.
    """
    row = adapter._device_info_row(("emulator-5554",))
    assert row == {"serial": "emulator-5554", "state": "unknown"}


def test_pm_path_skips_non_package_lines_before_the_real_one() -> None:
    """pm path noise (warnings, blank prefixes) does not hide the package line."""
    dev = _ScriptedShell({("pm", "path"): "WARNING: linker noise\npackage:/data/app/base.apk\n"})
    assert adapter._pm_path(dev, "com.example.app") == "/data/app/base.apk"


def test_pids_fallback_tolerates_a_matching_row_without_a_pid_column() -> None:
    """A ps row naming the package but carrying no digit contributes no pid.

    Some toybox ps layouts wrap columns; a matching line whose first three
    tokens are all text must be skipped rather than crash or invent a pid.
    """
    dev = _ScriptedShell(
        {
            ("pidof",): "/system/bin/sh: pidof: not found",
            ("ps", "-A"): "com.example.app wrapped row\n",
        }
    )
    assert adapter._pids_for_package(dev, "com.example.app") == []


# ---------------------------------------------------------------------------
# Constructor.


def test_backend_reports_available_when_adbutils_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present adbutils module flips available True and is kept for _client."""
    fake = types.ModuleType("adbutils")
    monkeypatch.setitem(sys.modules, "adbutils", fake)
    backend = AdbBackend()
    assert backend.available is True
    assert backend._adbutils is fake


# ---------------------------------------------------------------------------
# Device read-outs.


def test_properties_reports_has_more_when_the_page_fills() -> None:
    """More getprop rows than the cap set has_more and stop at the cap."""
    dump = "\n".join(f"[key.{index}]: [value{index}]" for index in range(5))
    payload = _backend_with(_ScriptedShell({("getprop",): dump})).properties(_SERIAL, limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_launch_wraps_a_non_adb_failure_as_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A monkey invocation dying outside adb's error shape is still structured."""

    def boom(dev: Any, args: Any, *, timeout: Any = None) -> str:
        raise ValueError("transport corrupted")

    monkeypatch.setattr(adapter, "_device_shell", boom)
    backend = _backend_with(SimpleNamespace())
    with pytest.raises(AdbError, match="launch failed") as excinfo:
        backend.launch(_SERIAL, "com.example.app")
    assert excinfo.value.code == "backend_error"


def test_force_stop_wraps_a_non_adb_failure_as_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """am force-stop dying outside adb's error shape is still structured."""

    def boom(dev: Any, args: Any, *, timeout: Any = None) -> str:
        raise ValueError("transport corrupted")

    monkeypatch.setattr(adapter, "_device_shell", boom)
    backend = _backend_with(SimpleNamespace())
    with pytest.raises(AdbError, match="force-stop failed") as excinfo:
        backend.force_stop(_SERIAL, "com.example.app")
    assert excinfo.value.code == "backend_error"


class _ForegroundDev:
    def __init__(self, current: Any) -> None:
        self._current = current

    def app_current(self, timeout: float | None = None) -> Any:
        del timeout
        return self._current


def test_current_activity_returns_the_foreground_package() -> None:
    """A readable foreground answers both package and activity."""
    dev = _ForegroundDev(SimpleNamespace(package="com.example.app", activity=".Main"))
    payload = _backend_with(dev).current_activity(_SERIAL)
    assert payload == {"package": "com.example.app", "activity": ".Main"}


def test_current_activity_refuses_an_empty_package_readout() -> None:
    """app_current answering without a package is a failed read, not success."""
    dev = _ForegroundDev(SimpleNamespace(package=None, activity=None))
    with pytest.raises(AdbError, match="failed to read current activity"):
        _backend_with(dev).current_activity(_SERIAL)


def test_current_activity_refuses_a_none_readout() -> None:
    """app_current answering None entirely is also a failed read."""
    with pytest.raises(AdbError, match="failed to read current activity"):
        _backend_with(_ForegroundDev(None)).current_activity(_SERIAL)


# ---------------------------------------------------------------------------
# Transfers and frida.


def test_pull_without_a_sync_surface_fails_structured(tmp_path: Path) -> None:
    """A device exposing sync=None skips the pre-stat and fails as backend_error.

    The pre-flight stat is best-effort; its absence must not turn the pull into
    an AttributeError that escapes the AdbError contract.
    """
    backend = _backend_with(SimpleNamespace(sync=None))
    with pytest.raises(AdbError, match="pull failed") as excinfo:
        backend.pull(_SERIAL, "/data/local/tmp/blob.bin", tmp_path / "blob.bin")
    assert excinfo.value.code == "backend_error"


def test_ensure_frida_server_refuses_a_bad_bind_host() -> None:
    """A bind_host with shell metacharacters never reaches the su command line."""
    backend = _backend_with(SimpleNamespace())
    with pytest.raises(AdbError, match="invalid bind_host"):
        backend.ensure_frida_server(_SERIAL, bind_host="bad host;rm")


# ---------------------------------------------------------------------------
# Forward bookkeeping.


class _FailingForwardDev:
    def __init__(self, exc: Exception, side_effect: Any = None) -> None:
        self._exc = exc
        self._side_effect = side_effect

    def forward(self, local: str, remote: str, timeout: float | None = None) -> None:
        del local, remote, timeout
        if self._side_effect is not None:
            self._side_effect()
        raise self._exc


def test_forward_adb_error_on_a_pre_existing_key_keeps_the_slot() -> None:
    """Re-forwarding a held spec that fails must not free the original slot.

    The reservation belongs to the earlier successful forward; dropping it on
    this call's failure would let release_forwards forget a live listener.
    """
    key = (_SERIAL, "tcp:5000")
    backend = _backend_with(_FailingForwardDev(AdbError("backend_error", "down")))
    backend._forwards = [key]
    with pytest.raises(AdbError, match="down"):
        backend.forward(_SERIAL, "tcp:5000", "tcp:6000")
    assert backend._forwards == [key]


def test_forward_generic_error_on_a_pre_existing_key_keeps_the_slot() -> None:
    """The non-AdbError arm makes the same keep-the-slot decision."""
    key = (_SERIAL, "tcp:5001")
    backend = _backend_with(_FailingForwardDev(OSError("socket died")))
    backend._forwards = [key]
    with pytest.raises(AdbError, match="forward failed"):
        backend.forward(_SERIAL, "tcp:5001", "tcp:6001")
    assert backend._forwards == [key]


def test_forward_adb_error_tolerates_a_reservation_already_dropped() -> None:
    """A reservation vanishing mid-call (release_forwards racing) is not an error."""
    backend = AdbBackend()
    backend._available = True
    key = (_SERIAL, "tcp:5002")

    def drop() -> None:
        backend._forwards.remove(key)

    dev = _FailingForwardDev(AdbError("backend_error", "down"), side_effect=drop)
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    with pytest.raises(AdbError, match="down"):
        backend.forward(_SERIAL, "tcp:5002", "tcp:6002")
    assert backend._forwards == []


def test_forward_generic_error_tolerates_a_reservation_already_dropped() -> None:
    """Same race tolerance on the non-AdbError arm."""
    backend = AdbBackend()
    backend._available = True
    key = (_SERIAL, "tcp:5003")

    def drop() -> None:
        backend._forwards.remove(key)

    dev = _FailingForwardDev(OSError("socket died"), side_effect=drop)
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    with pytest.raises(AdbError, match="forward failed"):
        backend.forward(_SERIAL, "tcp:5003", "tcp:6003")
    assert backend._forwards == []


def test_release_forwards_does_not_duplicate_a_retried_key() -> None:
    """A key failing twice in one sweep is re-queued once, not once per failure.

    Duplicated retry entries would grow the tracked list every sweep and eat
    the forward cap without any new forward existing on the adb server.
    """
    backend = AdbBackend()
    backend._available = True
    key = (_SERIAL, "tcp:5004")
    backend._forwards = [key, key]

    def gone(serial: str) -> Any:
        raise AdbError("not_found", "device gone", serial=serial)

    backend._device = gone  # type: ignore[method-assign]
    result = backend.release_forwards()
    assert result["removed"] == []
    assert len(result["failed"]) == 2
    assert backend._forwards == [key]
