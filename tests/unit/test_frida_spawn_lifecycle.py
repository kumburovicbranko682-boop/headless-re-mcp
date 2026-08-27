"""frida.spawn must never leave a spawned Android process behind, and must
classify every failure precisely.

``spawn`` launches a package suspended and then resumes it. The success path,
the package fail-fast, and the resume-that-hangs timeout are pinned elsewhere;
what is covered here is the rest of the failure surface, which only runs through
a live frida device:

* ``device.spawn`` itself faulting is ``backend_error`` (or ``timeout``) with
  nothing to clean up -- no pid was ever returned, so nothing is killed.
* ``device.resume`` faulting **after** a successful spawn must kill the spawned
  pid before surfacing the error -- otherwise a suspended process leaks on the
  device on every failed launch. The classification is preserved: an already
  classified ``FridaError`` is re-raised as-is, a raw fault becomes
  ``backend_error`` whose message says the process was killed, and a synchronous
  timeout becomes ``timeout``.

These are exercised with a fake device whose spawn/resume raise on demand and a
kill recorder -- no frida module, no emulator.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError

_PKG = "com.example.app"
_SPAWNED = 4242


class _SpawnDev:
    """A fake frida device with configurable spawn/resume faults."""

    def __init__(
        self,
        *,
        spawn_exc: BaseException | None = None,
        resume_exc: BaseException | None = None,
    ) -> None:
        self._spawn_exc = spawn_exc
        self._resume_exc = resume_exc
        self.killed: list[int] = []

    def spawn(self, package: str) -> int:
        del package
        if self._spawn_exc is not None:
            raise self._spawn_exc
        return _SPAWNED

    def resume(self, pid: int) -> None:
        del pid
        if self._resume_exc is not None:
            raise self._resume_exc

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


def _client_for(dev: _SpawnDev) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    return client


def test_a_spawn_fault_is_backend_error_with_nothing_to_kill() -> None:
    """spawn failing before it returns a pid leaks nothing: kill is not called."""
    dev = _SpawnDev(spawn_exc=RuntimeError("no such package on device"))
    with pytest.raises(FridaError) as caught:
        _client_for(dev).spawn("usb", _PKG)
    assert caught.value.code == "backend_error"
    assert "spawn failed" in caught.value.message
    assert dev.killed == []


def test_a_spawn_timeout_is_reported_as_timeout_with_nothing_to_kill() -> None:
    """A timeout on spawn itself maps to timeout, and there is no pid to kill."""
    dev = _SpawnDev(spawn_exc=RuntimeError("operation timed out"))
    with pytest.raises(FridaError) as caught:
        _client_for(dev).spawn("usb", _PKG)
    assert caught.value.code == "timeout"
    assert dev.killed == []


def test_a_resume_failure_kills_the_spawned_pid_then_reports_backend_error() -> None:
    """A raw resume fault after spawn must kill the pid, not leak it suspended."""
    dev = _SpawnDev(resume_exc=RuntimeError("resume refused"))
    with pytest.raises(FridaError) as caught:
        _client_for(dev).spawn("usb", _PKG)
    assert caught.value.code == "backend_error"
    assert "was killed" in caught.value.message
    assert caught.value.details.get("pid") == _SPAWNED
    assert dev.killed == [_SPAWNED]


def test_a_resume_timeout_kills_the_spawned_pid_then_reports_timeout() -> None:
    """A synchronous resume timeout still kills the spawned pid before raising."""
    dev = _SpawnDev(resume_exc=RuntimeError("resume timed out"))
    with pytest.raises(FridaError) as caught:
        _client_for(dev).spawn("usb", _PKG)
    assert caught.value.code == "timeout"
    assert dev.killed == [_SPAWNED]


def test_a_classified_resume_error_is_re_raised_as_is_after_the_kill() -> None:
    """A FridaError from resume keeps its code; the pid is still killed first.

    The resume branch has a dedicated ``except FridaError`` that re-raises the
    classified fault unchanged rather than flattening it to backend_error -- but
    it must still kill the spawned pid, or a classified failure would leak the
    process the raw-fault branch is careful to clean up.
    """
    dev = _SpawnDev(resume_exc=FridaError("permission_denied", "resume denied by policy"))
    with pytest.raises(FridaError) as caught:
        _client_for(dev).spawn("usb", _PKG)
    assert caught.value.code == "permission_denied"
    assert dev.killed == [_SPAWNED]
