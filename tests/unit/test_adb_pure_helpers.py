"""Pure adb validation/parsing helpers, pinned without adbutils or a device.

Three functions the device ops lean on ran only through a real-device path, so
none had a unit test even though each is a behavioral contract on untrusted
input or output:

* ``_check_forward_spec`` is the sole guard on what ``device.forward`` asks adb
  to bind -- it must admit only valid tcp/localabstract (and jdwp on the remote
  side), reject a five-digit non-port and ``tcp:0``, and refuse shell
  metacharacters -- so a bug here leaks adb-server listeners or worse.
* ``_is_host_error_output`` decides whether an offline device's stdout is a
  failure; it must fire only when *every* non-blank line is a host ``error:`` /
  ``adb:`` line, not when a real log line merely mentions "error".
* ``_frida_server_visible`` reads a ps table for the frida.server.ensure
  idempotency check and must answer true/false/None (unreadable) honestly.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import (
    AdbError,
    _check_forward_spec,
    _frida_server_visible,
    _is_host_error_output,
)


@pytest.mark.parametrize(
    "spec",
    ["tcp:1", "tcp:8080", "tcp:65535", "localabstract:foo", "localabstract:my.sock-1"],
)
def test_forward_spec_accepts_valid_local_endpoints(spec: str) -> None:
    _check_forward_spec(spec, side="local")


def test_forward_spec_accepts_valid_remote_endpoints_including_jdwp() -> None:
    _check_forward_spec("tcp:80", side="remote")
    _check_forward_spec("localabstract:svc", side="remote")
    _check_forward_spec("jdwp:1234", side="remote", allow_jdwp=True)


@pytest.mark.parametrize("spec", ["tcp:0", "tcp:70000", "tcp:99999"])
def test_forward_spec_rejects_out_of_range_tcp_ports(spec: str) -> None:
    with pytest.raises(AdbError) as info:
        _check_forward_spec(spec, side="local")
    assert info.value.code == "invalid_params"
    # The rejected spec travels back under the side key, so a caller sees which
    # endpoint it was.
    assert info.value.details.get("local") == spec


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "tcp:",
        "tcp:abc",
        "udp:80",
        "localabstract:has space",
        "localabstract:semi;colon",
        "tcp:80;rm -rf /",
        "/dev/null",
    ],
)
def test_forward_spec_rejects_garbage_and_shell_metacharacters(spec: str) -> None:
    with pytest.raises(AdbError) as info:
        _check_forward_spec(spec, side="remote")
    assert info.value.code == "invalid_params"


def test_forward_spec_admits_jdwp_only_where_it_is_permitted() -> None:
    """jdwp is a debugger endpoint only meaningful on the remote side; the local
    side (allow_jdwp defaulting False) must reject it."""
    with pytest.raises(AdbError) as info:
        _check_forward_spec("jdwp:1234", side="local")
    assert info.value.code == "invalid_params"


def test_host_error_output_true_when_every_line_is_a_host_error() -> None:
    assert _is_host_error_output("error: device offline") is True
    assert _is_host_error_output("adb: no devices/emulators found") is True
    assert _is_host_error_output("error: closed\nadb: device unauthorized") is True


def test_host_error_output_tolerates_leading_whitespace() -> None:
    assert _is_host_error_output("   error: device offline") is True


def test_host_error_output_false_for_empty_or_blank_text() -> None:
    assert _is_host_error_output("") is False
    assert _is_host_error_output("   \n   ") is False


def test_host_error_output_false_when_any_real_line_is_present() -> None:
    # A real log line that merely contains the word "error" is not a host error.
    assert _is_host_error_output("08-27 12:00:00 W/Auth: login error occurred") is False
    # Mixed: one host-error line plus one real line is not all-error, so the
    # result is a real (if noisy) reply, not a failure.
    assert _is_host_error_output("adb: something odd\npackage:com.example") is False


class _PsDev:
    """A device whose shell answers ps probes by exact command string."""

    def __init__(self, outputs: dict[str, str], *, raises: bool = False) -> None:
        self._outputs = outputs
        self._raises = raises

    def shell(self, args: Any, timeout: float | None = None) -> str:
        del timeout
        if self._raises:
            raise RuntimeError("device stalled")
        key = args if isinstance(args, str) else " ".join(args)
        return self._outputs.get(key, "")


def test_frida_server_visible_true_from_ps_a() -> None:
    dev = _PsDev({"ps -A": "root 123 1 0 0 ffff 0 S frida-server\n"})
    assert _frida_server_visible(dev) is True


def test_frida_server_visible_falls_back_to_bare_ps() -> None:
    """Some devices' ``ps -A`` omits it; the bare ``ps`` fallback still finds it."""
    dev = _PsDev(
        {"ps -A": "root 1 0 0 0 ffff 0 S init\n", "ps": "root 123 1 0 0 ffff 0 S frida-server\n"}
    )
    assert _frida_server_visible(dev) is True


def test_frida_server_visible_false_when_absent_from_both() -> None:
    dev = _PsDev({"ps -A": "root 1 0 0 0 ffff 0 S init\n", "ps": "root 1 0 0 0 ffff 0 S init\n"})
    assert _frida_server_visible(dev) is False


def test_frida_server_visible_none_when_the_process_list_is_unreadable() -> None:
    """A shell that fails outright leaves the probe null, not a false negative --
    so ensure does not push a second server on top of one it could not see."""
    dev = _PsDev({}, raises=True)
    assert _frida_server_visible(dev) is None
