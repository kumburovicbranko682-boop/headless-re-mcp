"""frida.spawn validates its package and never leaks a spawned process.

spawn launches an Android package suspended and then resumes it. Two things make
it safe: the package id is validated against the Android grammar before it ever
reaches ``device.spawn`` (the pid/identifier is model-controlled, and an
unvalidated value would be handed straight to frida), and a spawn that succeeds
but cannot be resumed must kill what it started -- otherwise a failed call
leaves a suspended process on the device forever. These pin the validation and
the kill-on-resume-failure contract, plus the timeout/backend_error labelling of
each leg, by driving the real method against a recording fake device.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _Device:
    """Records resume/kill so the leak-prevention contract is observable."""

    def __init__(
        self,
        *,
        spawn_result: Any = 4321,
        spawn_exc: BaseException | None = None,
        resume_exc: BaseException | None = None,
    ) -> None:
        self.spawn_result = spawn_result
        self.spawn_exc = spawn_exc
        self.resume_exc = resume_exc
        self.resumed: list[int] = []
        self.killed: list[int] = []

    def spawn(self, package: str) -> int:
        if self.spawn_exc is not None:
            raise self.spawn_exc
        return self.spawn_result

    def resume(self, pid: int) -> None:
        if self.resume_exc is not None:
            raise self.resume_exc
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


def _client(device: _Device) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


def test_spawn_requires_a_non_empty_package() -> None:
    with pytest.raises(FridaError) as info:
        _client(_Device()).spawn("usb", "   ")
    assert info.value.code == "invalid_params"
    assert "package is required" in info.value.message


def test_spawn_rejects_a_value_that_is_not_an_android_package_id() -> None:
    """A malformed identifier is refused before it reaches device.spawn.

    The package flows in from model arguments; validating against the Android
    grammar keeps a stray value (a path, a flag, whitespace) from being handed
    to frida as a spawn target.
    """
    device = _Device()
    for bad in ("not a package", "/system/bin/sh", "com", "-rf", "a..b"):
        with pytest.raises(FridaError) as info:
            _client(device).spawn("usb", bad)
        assert info.value.code == "invalid_params"
        assert info.value.details.get("package") == bad
    assert device.resumed == []


def test_spawn_failure_is_backend_error_naming_the_package() -> None:
    device = _Device(spawn_exc=RuntimeError("unable to find application"))
    with pytest.raises(FridaError) as info:
        _client(device).spawn("usb", "com.example.app")
    assert info.value.code == "backend_error"
    assert "spawn failed" in info.value.message
    assert info.value.details.get("package") == "com.example.app"
    assert device.killed == []


def test_spawn_timeout_keeps_the_timeout_code() -> None:
    device = _Device(spawn_exc=RuntimeError("operation timed out"))
    with pytest.raises(FridaError) as info:
        _client(device).spawn("usb", "com.example.app", timeout=5.0)
    assert info.value.code == "timeout"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    """A spawn that cannot be resumed must not leave a suspended process behind.

    device.spawn succeeded, so a pid now exists on the device; when resume then
    fails, spawn kills that pid before surfacing the error, and reports it so the
    caller knows the process is gone rather than lingering paused.
    """
    device = _Device(spawn_result=4321, resume_exc=RuntimeError("resume rejected"))
    with pytest.raises(FridaError) as info:
        _client(device).spawn("usb", "com.example.app")
    assert info.value.code == "backend_error"
    assert "resume failed" in info.value.message
    assert info.value.details.get("pid") == 4321
    assert device.killed == [4321]


def test_spawn_kills_the_process_when_resume_times_out() -> None:
    device = _Device(spawn_result=4321, resume_exc=RuntimeError("resume timed out"))
    with pytest.raises(FridaError) as info:
        _client(device).spawn("usb", "com.example.app", timeout=5.0)
    assert info.value.code == "timeout"
    assert device.killed == [4321]


def test_spawn_kills_the_process_and_reraises_a_frida_error_from_resume() -> None:
    """A classified error from resume is preserved, and the process still dies."""
    device = _Device(
        spawn_result=4321,
        resume_exc=FridaError("permission_denied", "resume not allowed"),
    )
    with pytest.raises(FridaError) as info:
        _client(device).spawn("usb", "com.example.app")
    assert info.value.code == "permission_denied"
    assert device.killed == [4321]


def test_spawn_success_resumes_and_returns_the_pid() -> None:
    device = _Device(spawn_result=4321)
    payload = _client(device).spawn("usb", "com.example.app")
    assert payload == {"package": "com.example.app", "pid": 4321, "device": "usb"}
    assert device.resumed == [4321]
    assert device.killed == []
