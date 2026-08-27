"""device.launch must not call a still-settling launch a failure.

``monkey`` returns the moment it injects the LAUNCHER intent, but the activity
it starts reaches the foreground a beat later. A single immediate ``app_current``
read then reports ``launched: false`` for a launch that in fact succeeded, and an
unattended caller that trusts that field gives up on an app that is coming up.
The backend polls ``app_current`` for a bounded settle window instead; these
tests pin that contract without needing a real device.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend


class _FakeDevice:
    def __init__(self, foreground_sequence: list[Any]) -> None:
        self._seq = list(foreground_sequence)
        self.app_current_calls = 0
        self.shell_calls: list[Any] = []

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        self.shell_calls.append(args)
        return "Events injected: 1"

    def app_current(self) -> SimpleNamespace:
        self.app_current_calls += 1
        index = min(self.app_current_calls - 1, len(self._seq) - 1)
        value = self._seq[index]
        if isinstance(value, Exception):
            raise value
        return SimpleNamespace(package=value, activity=f"{value}/.Main")


def _backend(device: _FakeDevice) -> AdbBackend:
    class AdbClient:
        def __init__(self, **kwargs: Any) -> None:
            del kwargs

        def device(self, serial: str | None = None) -> _FakeDevice:
            del serial
            return device

    backend = AdbBackend()
    backend._available = True
    backend._adbutils = SimpleNamespace(AdbClient=AdbClient)
    return backend


@pytest.fixture(autouse=True)
def _fake_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advance a fake monotonic clock on each sleep so the poll loop is instant."""
    clock = {"t": 0.0}
    fake_time = SimpleNamespace(
        monotonic=lambda: clock["t"],
        sleep=lambda seconds: clock.__setitem__("t", clock["t"] + seconds),
    )
    monkeypatch.setattr("headless_re_mcp.backends.adb.client.time", fake_time)


def test_launch_waits_for_the_app_to_settle_to_foreground() -> None:
    """The target is not foreground on the first read, but becomes so shortly.

    A single-shot check would have returned launched:false here; the settle poll
    must keep reading until the app the caller launched is actually resumed.
    """
    device = _FakeDevice(
        ["com.other.launcher", "com.other.launcher", "com.example.app"]
    )
    result = _backend(device).launch("emulator-5554", "com.example.app")
    assert result["launched"] is True
    assert result["foreground"] == "com.example.app"
    # It cannot have concluded success from the first read; it had to poll.
    assert device.app_current_calls >= 3


def test_launch_reports_false_when_the_app_never_comes_foreground() -> None:
    """A launch that never resumes the target stays launched:false, honestly.

    The field must still be false (not None, not True), and the backend must have
    genuinely waited rather than deciding from one read.
    """
    device = _FakeDevice(["com.other.launcher"])
    result = _backend(device).launch("emulator-5554", "com.example.app")
    assert result["launched"] is False
    assert result["foreground"] == "com.other.launcher"
    assert device.app_current_calls > 1


def test_launch_reports_none_when_foreground_is_unreadable() -> None:
    """If app_current cannot be read at all, launched is None with a note.

    An unreadable foreground is not the same as a failed launch: the caller is
    told the launch intent went out but the result could not be verified.
    """
    device = _FakeDevice([RuntimeError("dumpsys unavailable")])
    result = _backend(device).launch("emulator-5554", "com.example.app")
    assert result["launched"] is None
    assert "could not read foreground" in result["note"]


def test_launch_returns_immediately_when_already_foreground() -> None:
    """The common case: the app is resumed by the first read, so no waiting."""
    device = _FakeDevice(["com.example.app"])
    result = _backend(device).launch("emulator-5554", "com.example.app")
    assert result["launched"] is True
    assert result["foreground"] == "com.example.app"
    assert device.app_current_calls == 1
