"""frida.server.ensure binds loopback by default; network exposure is opt-in.

frida-server's -l flag chooses the listen interface. The launcher hardcoded
0.0.0.0, so every ensure call published the instrumentation port on every
interface the device could route -- a root-level control channel reachable by
anything on the same network, with no key. Loopback is the safe default: the
USB/adb transport and an adb forward still reach it (that is how a local
emulator or a USB device is driven), while a host that merely shares the
network cannot. A remote-by-IP device is the one case that needs the wider
bind, so 0.0.0.0 stays available -- but only when the caller names it.

The value reaches a `su -c '...'` command line, so bind_host is validated
against a strict host set before it is ever interpolated; a colon, a space, or
a shell metacharacter is refused rather than run.
"""

from __future__ import annotations

from typing import Any

import pytest

import headless_re_mcp.backends.adb.client as adb
from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


def _capture_launch(monkeypatch: Any) -> list[str]:
    """Record every device shell command and pretend frida-server never shows."""
    commands: list[str] = []

    def fake_shell(dev: Any, args: Any, *, timeout: float = 30.0) -> str:
        del dev, timeout
        commands.append(args if isinstance(args, str) else " ".join(args))
        return ""

    monkeypatch.setattr(adb, "_device_shell", fake_shell)
    monkeypatch.setattr(adb, "_frida_server_visible", lambda dev: False)
    return commands


def _backend(monkeypatch: Any) -> AdbBackend:
    backend = AdbBackend()
    # The device handle is only a token here; every call that would touch it is
    # intercepted, so the command string is all that is under test.
    monkeypatch.setattr(backend, "_device", lambda serial: object())
    return backend


def test_default_bind_host_is_loopback(monkeypatch: Any) -> None:
    """With no bind_host the launcher pins 127.0.0.1, never 0.0.0.0."""
    commands = _capture_launch(monkeypatch)
    backend = _backend(monkeypatch)
    backend.ensure_frida_server("emulator-5554", port=27042)
    launch = next(command for command in commands if "nohup" in command)
    assert "-l 127.0.0.1:27042" in launch
    assert "0.0.0.0" not in launch


def test_bind_host_can_be_opened_explicitly(monkeypatch: Any) -> None:
    """A caller that needs remote-by-IP reach names 0.0.0.0 and gets it."""
    commands = _capture_launch(monkeypatch)
    backend = _backend(monkeypatch)
    backend.ensure_frida_server("emulator-5554", port=27042, bind_host="0.0.0.0")
    launch = next(command for command in commands if "nohup" in command)
    assert "-l 0.0.0.0:27042" in launch


@pytest.mark.parametrize(
    "bad",
    ["1.2.3.4; rm -rf /", "127.0.0.1:22", "$(id)", "a b", "10.0.0.5 && reboot", ""],
)
def test_invalid_bind_host_is_refused_before_any_launch(monkeypatch: Any, bad: str) -> None:
    """A metacharacter, a colon, or an empty host is rejected and nothing runs."""
    commands = _capture_launch(monkeypatch)
    backend = _backend(monkeypatch)
    with pytest.raises(AdbError) as caught:
        backend.ensure_frida_server("emulator-5554", bind_host=bad)
    assert caught.value.code == "invalid_params"
    assert commands == []


@pytest.mark.parametrize(
    "bad",
    [
        "data/local/tmp/frida",  # no leading slash: not an absolute device path
        "/data/local/tmp/frida; reboot",  # command separator
        "/data/local/tmp/$(id)",  # command substitution
        "/data/local/tmp/`id`",  # backtick substitution
        "/data/local/tmp/frida server",  # whitespace splits the argv
        "/data/local/tmp/'evil'",  # a quote reshapes the su -c string
        "/data/local/tmp/x&&reboot",  # command chaining
        "",  # empty is not a path at all
    ],
)
def test_invalid_remote_path_is_refused_before_any_launch(monkeypatch: Any, bad: str) -> None:
    """remote_path lands in the same su -c string, so it is validated too.

    The launcher interpolates remote_path into ``su -c 'nohup <remote_path> -l
    ...'`` exactly as it does bind_host, so a metacharacter here is the same
    root-shell injection: a path carrying ``;``, ``$(...)``, backticks, a
    quote, whitespace, or ``&&`` -- or one that is not even absolute -- must be
    refused as invalid_params before any device command runs, not passed to a
    root shell. The push/chmod that would precede the launch use an argv list
    (no shell), so this guard is the one line between the argument and ``su``.
    """
    commands = _capture_launch(monkeypatch)
    backend = _backend(monkeypatch)
    with pytest.raises(AdbError) as caught:
        backend.ensure_frida_server("emulator-5554", remote_path=bad)
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("remote_path") == bad
    assert commands == []


def test_valid_remote_path_reaches_the_launch_verbatim(monkeypatch: Any) -> None:
    """A well-formed device path is accepted and used as the frida-server path."""
    commands = _capture_launch(monkeypatch)
    backend = _backend(monkeypatch)
    backend.ensure_frida_server(
        "emulator-5554", port=27042, remote_path="/data/local/tmp/fs"
    )
    launch = next(command for command in commands if "nohup" in command)
    assert "nohup /data/local/tmp/fs -l 127.0.0.1:27042" in launch
