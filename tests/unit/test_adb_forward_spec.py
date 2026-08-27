"""adb forward endpoints are validated, port range included.

``connect`` refuses a port outside 1..65535, but ``forward`` used to accept any
one-to-five digit run, so ``tcp:70000`` reached adb as a bind request it could
only reject with an opaque backend error. These tests hold ``forward`` to the
same boundary check ``connect`` makes, while keeping every spec adb genuinely
accepts -- including ``tcp:0`` (allocate a free port) and ``jdwp:`` on the
remote side.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


class _Dev:
    def forward(self, local: str, remote: str) -> None:
        del local, remote


def _backend() -> AdbBackend:
    backend = AdbBackend()
    backend._device = lambda serial: _Dev()  # type: ignore[method-assign]
    return backend


@pytest.mark.parametrize("port", ["65536", "70000", "99999"])
def test_local_tcp_port_above_the_range_is_refused(port: str) -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", f"tcp:{port}", "tcp:27042")
    assert caught.value.code == "invalid_params"
    assert "port" in caught.value.message
    # The offending value travels in the details for the caller.
    assert caught.value.details.get("local") == f"tcp:{port}"


@pytest.mark.parametrize("port", ["65536", "70000", "99999"])
def test_remote_tcp_port_above_the_range_is_refused(port: str) -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:27042", f"tcp:{port}")
    assert caught.value.code == "invalid_params"
    assert caught.value.details.get("remote") == f"tcp:{port}"


@pytest.mark.parametrize("local", ["tcp:0", "tcp:1", "tcp:27042", "tcp:65535"])
def test_in_range_tcp_ports_are_accepted(local: str) -> None:
    backend = _backend()
    result = backend.forward("emulator-5554", local, "tcp:27042")
    assert result["local"] == local
    assert backend._forwards == [("emulator-5554", local)]


def test_localabstract_and_jdwp_specs_still_work() -> None:
    backend = _backend()
    result = backend.forward("emulator-5554", "localabstract:frida", "jdwp:1234")
    assert result == {"local": "localabstract:frida", "remote": "jdwp:1234"}


def test_jdwp_is_only_valid_on_the_remote_side() -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "jdwp:1234", "tcp:27042")
    assert caught.value.code == "invalid_params"
    assert "local" in caught.value.message


@pytest.mark.parametrize(
    "spec",
    ["", "tcp:", "tcp:abc", "udp:5555", "tcp:80 rm -rf", "localabstract:bad/name"],
)
def test_malformed_specs_are_refused(spec: str) -> None:
    backend = _backend()
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", spec, "tcp:27042")
    assert caught.value.code == "invalid_params"


def test_an_out_of_range_port_is_refused_before_a_device_is_touched() -> None:
    """Validation runs ahead of the device lookup, so a bad spec costs nothing."""
    backend = AdbBackend()

    def _boom(serial: str) -> Any:
        raise AssertionError("device must not be resolved for an invalid spec")

    backend._device = _boom  # type: ignore[method-assign]
    with pytest.raises(AdbError) as caught:
        backend.forward("emulator-5554", "tcp:70000", "tcp:27042")
    assert caught.value.code == "invalid_params"
    assert backend._forwards == []
