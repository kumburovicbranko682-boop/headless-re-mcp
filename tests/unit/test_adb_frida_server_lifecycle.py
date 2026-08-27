"""frida.server.ensure: push/launch outcomes must be reported honestly.

The bind_host/remote_path validation is pinned elsewhere; this covers what the
op actually does and returns once the arguments are accepted:

  * if frida-server is already up, it does nothing and says so (pushed False) --
    the op is meant to be idempotent, not to re-push on every call.
  * given a server_binary it pushes and chmods it, and a push that fails is a
    backend_error, not a silent launch of a binary that was never delivered; a
    binary path that does not exist is not_found before any device call.
  * the launch is best-effort under ``su``. A launch that raises (often a bounded
    timeout on a device that actually did start it) returns a "verify manually"
    note rather than failing outright, and a launch that returns cleanly but
    leaves nothing in ``ps`` reports running False with a note -- so an agent is
    never told frida-server is up when it is not.

These drive a fake device and stubbed ``_device_shell`` / ``_frida_server_visible``
-- no adb, no emulator -- exactly where the push/launch decisions live.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.adb.client as adb
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _Sync:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.pushed: list[tuple[str, str]] = []

    def push(self, local: str, remote: str, timeout: float | None = None) -> None:
        del timeout
        if self.fail:
            raise RuntimeError("no space left on device")
        self.pushed.append((local, remote))


class _Dev:
    def __init__(self, *, push_fails: bool = False) -> None:
        self.sync = _Sync(fail=push_fails)


def _backend(dev: _Dev) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._device = lambda serial: dev  # type: ignore[method-assign]
    return backend


def _stub_visibility(monkeypatch: Any, sequence: list[bool]) -> None:
    """_frida_server_visible answers from a fixed sequence (last value repeats).

    ensure calls it once up front and again after the launch, so a two-element
    sequence scripts 'not there, then there' (a real start) or 'not there, still
    not there' (a launch that did nothing).
    """
    values = iter(sequence)

    def fake(dev: Any) -> bool:
        del dev
        return next(values, sequence[-1])

    monkeypatch.setattr(adb, "_frida_server_visible", fake)


def _record_shells(monkeypatch: Any, *, boom_on: str | None = None) -> list[str]:
    commands: list[str] = []

    def fake_shell(dev: Any, args: Any, *, timeout: float = 30.0) -> str:
        del dev, timeout
        text = args if isinstance(args, str) else " ".join(args)
        commands.append(text)
        if boom_on is not None and boom_on in text:
            raise RuntimeError("su: not found")
        return ""

    monkeypatch.setattr(adb, "_device_shell", fake_shell)
    return commands


def test_an_already_running_server_is_left_alone(monkeypatch: Any) -> None:
    """When ps already shows frida-server, ensure pushes and launches nothing."""
    _stub_visibility(monkeypatch, [True])
    shells = _record_shells(monkeypatch)
    dev = _Dev()

    result = _backend(dev).ensure_frida_server("emulator-5554", port=27042)

    assert result == {"running": True, "pushed": False, "port": 27042}
    assert shells == []
    assert dev.sync.pushed == []


def test_a_provided_binary_is_pushed_chmodded_and_launched(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """A server_binary is delivered, made executable, then started and confirmed.

    The success shape an operator relies on: the local binary lands at
    remote_path, is chmod 755, then launched under su -- and because ps shows it
    afterwards, the reply is running True with pushed True.
    """
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    _stub_visibility(monkeypatch, [False, True])
    shells = _record_shells(monkeypatch)
    dev = _Dev()

    result = _backend(dev).ensure_frida_server(
        "emulator-5554", server_binary=str(binary), port=27042
    )

    assert result == {"running": True, "pushed": True, "port": 27042}
    assert dev.sync.pushed == [(str(binary), "/data/local/tmp/frida-server")]
    assert any(cmd.startswith("chmod 755 ") for cmd in shells)
    assert any("nohup /data/local/tmp/frida-server -l 127.0.0.1:27042" in cmd for cmd in shells)


def test_a_missing_binary_is_not_found_before_any_device_call(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """A server_binary path that does not exist is refused before push/launch."""
    _stub_visibility(monkeypatch, [False])
    shells = _record_shells(monkeypatch)
    dev = _Dev()

    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "does-not-exist")
        )
    assert caught.value.code == "not_found"
    assert dev.sync.pushed == []
    assert shells == []


def test_a_failed_push_is_a_backend_error_not_a_phantom_launch(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """If the binary cannot be pushed, ensure fails instead of launching nothing.

    Launching remote_path after a failed push would run a stale or absent binary;
    the push failure must surface as a backend_error naming the cause.
    """
    binary = tmp_path / "frida-server"
    binary.write_bytes(b"\x7fELF")
    _stub_visibility(monkeypatch, [False])
    shells = _record_shells(monkeypatch)
    dev = _Dev(push_fails=True)

    with pytest.raises(AdbError) as caught:
        _backend(dev).ensure_frida_server("emulator-5554", server_binary=str(binary))
    assert caught.value.code == "backend_error"
    assert "failed to push frida-server" in caught.value.message
    # The launch never ran: no su command was issued after the push failed.
    assert not any("nohup" in cmd for cmd in shells)


def test_a_launch_that_raises_returns_a_verify_manually_note(monkeypatch: Any) -> None:
    """A bounded launch that throws often means it started -- report, don't fail.

    The su launch is deadline-bounded, and a device that actually started
    frida-server can trip that deadline. Rather than call the whole op a failure,
    ensure returns a note asking the operator to verify, carrying the current
    visibility rather than a raised exception.
    """
    _stub_visibility(monkeypatch, [False, False])
    _record_shells(monkeypatch, boom_on="nohup")
    dev = _Dev()

    result = _backend(dev).ensure_frida_server("emulator-5554", port=27042)

    assert result["running"] is False
    assert result["port"] == 27042
    assert "verify manually" in result["note"]


def test_a_clean_launch_that_shows_nothing_reports_not_running(monkeypatch: Any) -> None:
    """A launch that returns but leaves nothing in ps must not claim success.

    The command coming back cleanly is not proof frida-server is up; if ps still
    shows nothing, the reply is running False with a note, so an agent does not
    proceed to attach against a server that never started.
    """
    _stub_visibility(monkeypatch, [False, False])
    _record_shells(monkeypatch)
    dev = _Dev()

    result = _backend(dev).ensure_frida_server("emulator-5554", port=27042)

    assert result["running"] is False
    assert "not visible in ps" in result["note"]
