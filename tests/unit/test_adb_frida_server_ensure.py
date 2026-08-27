"""ensure_frida_server is the most privileged device mutation, so it must
degrade honestly rather than claim a root launch it cannot confirm.

``ensure_frida_server`` pushes a binary to the device and starts it under
``su`` -- a root operation whose success adb's own return does not prove. The
already-running short-circuit and the "launched but not visible in ps" note are
pinned elsewhere; what is covered here is the rest of the push-and-launch path,
which only runs through the live adbutils backend:

* a confirmed launch reports ``running`` **and** whether the binary was pushed,
* a push that fails is ``backend_error`` -- the launch is never attempted,
* a launch call that faults (a blocking ``su`` prompt, a timeout) does not claim
  ``running`` True; it returns the device's real ``ps`` verdict with a note.

These are exercised with an injected fake device and a real temp binary -- no
adbutils, no rooted emulator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _Sync:
    """A fake adbutils sync channel that records or refuses a push."""

    def __init__(self, *, raises: bool = False, adb_error: bool = False) -> None:
        self._raises = raises
        self._adb_error = adb_error
        self.pushed: list[tuple[str, str]] = []

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        if self._adb_error:
            raise AdbError("timeout", "adb timed out pushing frida-server")
        if self._raises:
            raise RuntimeError("adb: device offline during push")
        self.pushed.append((local, remote))


class _FridaDev:
    """Routes the ps probe, chmod, and su launch for ensure_frida_server.

    ``visible_after_launch`` decides what ``ps`` reports once the ``su`` line has
    run: this lets a single device answer "not running" on the pre-push probe and
    "running" on the post-launch probe, the real sequence the method walks.
    """

    def __init__(
        self,
        *,
        sync: _Sync | None = None,
        visible_after_launch: bool = False,
        su_raises: bool = False,
    ) -> None:
        self.sync = sync
        self._visible_after_launch = visible_after_launch
        self._su_raises = su_raises
        self._launched = False
        self.chmodded: list[tuple[str, ...]] = []
        self.su_calls = 0

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        if isinstance(args, str) and args.startswith("su"):
            self.su_calls += 1
            if self._su_raises:
                raise RuntimeError("su prompt blocked")
            self._launched = True
            return ""
        if isinstance(args, list) and args[:1] == ["chmod"]:
            self.chmodded.append(tuple(args))
            return ""
        # Anything else is the `ps -A` / `ps` frida-server probe.
        if self._launched and self._visible_after_launch:
            return "u0_a1  1234  /data/local/tmp/frida-server\n"
        return "root  1  init\n"


def _backend_with(dev: _FridaDev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _server_binary(tmp_path: Path) -> str:
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF fake frida-server")
    return str(binary)


def test_a_confirmed_launch_reports_running_and_that_it_pushed(tmp_path: Path) -> None:
    """Pushing a binary, chmod-ing it, then seeing it in ps is running+pushed."""
    sync = _Sync()
    dev = _FridaDev(sync=sync, visible_after_launch=True)
    result = _backend_with(dev).ensure_frida_server(
        "emulator-5554", server_binary=_server_binary(tmp_path)
    )
    assert result == {"running": True, "pushed": True, "port": 27042}
    # The binary was transferred and made executable before the launch.
    assert len(sync.pushed) == 1
    assert dev.chmodded == [("chmod", "755", "/data/local/tmp/frida-server")]
    assert dev.su_calls == 1


def test_a_push_failure_is_backend_error_and_never_launches(tmp_path: Path) -> None:
    """A failed transfer stops before su: the device is never asked to launch."""
    dev = _FridaDev(sync=_Sync(raises=True), visible_after_launch=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).ensure_frida_server(
            "emulator-5554", server_binary=_server_binary(tmp_path)
        )
    assert caught.value.code == "backend_error"
    assert "failed to push frida-server" in caught.value.message
    # The launch line must not have run once the push failed.
    assert dev.su_calls == 0


def test_a_push_that_fails_as_an_adberror_keeps_its_code_and_never_launches(
    tmp_path: Path,
) -> None:
    """A classified push fault (a timeout) is re-raised as-is, not flattened.

    The backend_error path wraps a raw exception; this is the other branch --
    a push that already handed back a classified AdbError must keep its code
    (timeout here) rather than being re-labelled backend_error, and the launch
    is still never attempted.
    """
    dev = _FridaDev(sync=_Sync(adb_error=True), visible_after_launch=True)
    with pytest.raises(AdbError) as caught:
        _backend_with(dev).ensure_frida_server(
            "emulator-5554", server_binary=_server_binary(tmp_path)
        )
    assert caught.value.code == "timeout"
    assert dev.su_calls == 0


def test_a_launch_that_faults_does_not_claim_running_true() -> None:
    """A su call that throws returns the real ps verdict with a note, not True.

    A blocking su prompt or a timeout on the launch line is caught: the method
    re-probes ps and reports that verdict (False here) rather than assuming the
    launch that just faulted actually took.
    """
    dev = _FridaDev(sync=None, visible_after_launch=False, su_raises=True)
    result = _backend_with(dev).ensure_frida_server("emulator-5554")
    assert result["running"] is False
    assert result["pushed"] is False
    assert "verify manually" in str(result.get("note", ""))
    assert dev.su_calls == 1
