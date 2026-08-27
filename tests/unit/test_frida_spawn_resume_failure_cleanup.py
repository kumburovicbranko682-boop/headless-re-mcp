"""``frida.spawn`` must not leak a suspended process when resume fails outright.

``frida.spawn`` launches the target *suspended* and only becomes a running app
once ``device.resume`` succeeds. So the spawn and the resume are two steps, and
if the second one fails the first has already created a process that is frozen,
holding a slot, waiting for a resume that is never coming. ``work()`` handles
that inside its own ``try`` -- distinct from the timeout path::

    spawned = int(_invoke(device.spawn, pkg, timeout=deadline))
    pids.append(spawned)
    try:
        _invoke(device.resume, spawned, timeout=deadline)
    except FridaError:
        with contextlib.suppress(Exception):
            device.kill(spawned)
        raise                                   # keep the original code/message
    except Exception as exc:
        with contextlib.suppress(Exception):
            device.kill(spawned)
        if _is_timeout(exc):
            raise _timeout_error(deadline) from exc
        raise FridaError(
            "backend_error",
            f"spawned pid {spawned} but resume failed; process was killed: {exc}",
            package=pkg, pid=spawned,
        ) from exc

The only existing spawn-cleanup test makes ``resume`` *hang* (``sleep(10)``),
which trips the deadline and runs ``on_timeout=_kill_spawned`` -- the outer
timeout path, never this inner ``except``. A resume that fails *synchronously*
(the far more common "process is not responding", a permission refusal, a device
that dropped) takes this branch instead, and three behaviours here are
load-bearing and unpinned:

* **A generic resume failure kills the orphan and says so.** The spawned pid is
  killed and the error is a ``backend_error`` whose message names the pid and
  states the process was killed, with ``pid`` in the details. Drop the
  ``device.kill`` and every failed resume leaks a frozen process; without the
  guard a caller cannot even tell which pid to clean up by hand.

* **A ``FridaError`` from resume keeps its own code.** ``_invoke`` can surface a
  structured failure -- ``permission_denied`` when the device refuses to resume.
  The dedicated ``except FridaError`` still kills the pid but re-raises the
  original, so a permission problem stays ``permission_denied`` and is not
  flattened into a generic ``backend_error`` the caller would retry blindly.

* **A failing kill does not mask the real error.** Cleanup is best-effort
  (``contextlib.suppress``): if ``device.kill`` itself throws, the resume
  failure still surfaces rather than being replaced by the kill's exception.

These drive ``FridaClient.spawn`` directly with a fake device -- no frida, no
USB -- and a generous timeout so the failure is synchronous, not the deadline.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client(device: object) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


class _ResumeRaises:
    """A device that spawns cleanly but fails resume with a chosen exception."""

    def __init__(self, *, spawn_pid: int, resume_exc: Exception) -> None:
        self._spawn_pid = spawn_pid
        self._resume_exc = resume_exc
        self.killed: list[int] = []

    def spawn(self, package: str) -> int:
        del package
        return self._spawn_pid

    def resume(self, pid: int) -> None:
        del pid
        raise self._resume_exc

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


def test_a_generic_resume_failure_kills_the_orphan_and_names_the_pid() -> None:
    """Resume raising a plain error kills the frozen pid and reports backend_error.

    The suspended process must not be left behind, and the caller must learn
    which pid was involved: a bare "resume failed" with no kill leaks a process
    and no pid.
    """
    device = _ResumeRaises(spawn_pid=4242, resume_exc=RuntimeError("not responding"))
    with pytest.raises(FridaError) as caught:
        _client(device).spawn("usb", "com.example.app", timeout=5)
    assert caught.value.code == "backend_error"
    assert device.killed == [4242]
    assert caught.value.details.get("pid") == 4242
    assert caught.value.details.get("package") == "com.example.app"
    assert "resume failed" in caught.value.message
    assert "killed" in caught.value.message
    assert "4242" in caught.value.message


def test_a_structured_resume_failure_keeps_its_own_error_code() -> None:
    """A permission_denied from resume stays permission_denied, not backend_error.

    The device refusing to resume is a distinct, non-retryable condition. The
    dedicated FridaError branch still kills the pid but must re-raise the
    original error so its code and message survive intact.
    """
    device = _ResumeRaises(
        spawn_pid=777,
        resume_exc=FridaError("permission_denied", "device refused to resume"),
    )
    with pytest.raises(FridaError) as caught:
        _client(device).spawn("usb", "com.example.app", timeout=5)
    assert caught.value.code == "permission_denied"
    assert caught.value.message == "device refused to resume"
    assert device.killed == [777]


def test_a_failing_kill_does_not_mask_the_resume_failure() -> None:
    """Best-effort cleanup: a kill that throws must not replace the real error.

    ``contextlib.suppress`` swallows the kill's own exception so the resume
    failure is still what the caller sees -- not a confusing error about the
    cleanup step.
    """

    class _KillAlsoFails(_ResumeRaises):
        def kill(self, pid: int) -> None:
            raise RuntimeError("kill failed too")

    device = _KillAlsoFails(spawn_pid=999, resume_exc=RuntimeError("resume boom"))
    with pytest.raises(FridaError) as caught:
        _client(device).spawn("usb", "com.example.app", timeout=5)
    assert caught.value.code == "backend_error"
    assert "resume failed" in caught.value.message
    assert "resume boom" in caught.value.message
