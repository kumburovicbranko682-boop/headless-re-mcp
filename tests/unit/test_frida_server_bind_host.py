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

from pathlib import Path
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


def test_cheap_local_inputs_are_validated_before_resolving_the_device(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """A bad remote_path/bind_host or a missing server_binary must fail before _device.

    ensure_frida_server resolved the device first and validated remote_path,
    bind_host, and the server_binary's existence after -- so on a host where the
    adb server or device is unreachable, a malformed remote_path or a typo'd
    binary path surfaced as the resolver's device error instead of the precise
    invalid_params / not_found the input warranted, and paid the cost of reaching
    the adb server first. The checks now run before _device, exactly like
    install()/push()/forward(): proven by a resolver that records every call and
    must stay empty across all three malformed inputs.
    """
    resolved: list[str] = []

    def _recording_device(serial: str) -> object:
        resolved.append(serial)
        return object()

    backend = AdbBackend()
    monkeypatch.setattr(backend, "_device", _recording_device)

    with pytest.raises(AdbError) as bad_remote:
        backend.ensure_frida_server("emulator-5554", remote_path="not-absolute")
    assert bad_remote.value.code == "invalid_params"

    with pytest.raises(AdbError) as bad_bind:
        backend.ensure_frida_server("emulator-5554", bind_host="1.2.3.4; rm -rf /")
    assert bad_bind.value.code == "invalid_params"

    with pytest.raises(AdbError) as missing_binary:
        backend.ensure_frida_server(
            "emulator-5554", server_binary=str(tmp_path / "no-such-frida-server")
        )
    assert missing_binary.value.code == "not_found"

    assert resolved == [], "a bad local input reached _device before validation"


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 999999])
def test_an_out_of_range_port_is_refused_before_resolving_the_device(
    monkeypatch: Any, bad_port: int
) -> None:
    """An out-of-range port fails as invalid_params before _device and the launch.

    The frida.server.ensure schema bounds port to 1..65535, but the agent and
    OpenAI-bridge transports call the handler directly and skip that pydantic
    check -- only the MCP path runs it. The backend used to trust the value and
    interpolate it straight into `su -c '... -l host:port ...'`, so an
    out-of-range port from a non-MCP caller became an opaque frida-server bind
    failure. It now re-validates like proxy.start: a bad port is refused up
    front, before the device is resolved (recording resolver stays empty) and
    long before the su launch line is built.
    """
    resolved: list[str] = []

    def _recording_device(serial: str) -> object:
        resolved.append(serial)
        return object()

    backend = AdbBackend()
    monkeypatch.setattr(backend, "_device", _recording_device)

    with pytest.raises(AdbError) as caught:
        backend.ensure_frida_server("emulator-5554", port=bad_port)
    assert caught.value.code == "invalid_params"
    assert caught.value.details["port"] == bad_port
    assert resolved == [], "an out-of-range port reached _device"
