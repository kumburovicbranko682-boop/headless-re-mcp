"""device.connect must say when a connected device is not yet usable.

adb answers "connected to host:port" the instant the TCP transport is up, but
the device can still be offline or unauthorized and reject every command until
it finishes booting or the RSA key is accepted. Reported as connected true
alone, that reads as "ready", so an unattended caller fires info/screenshot/
install at a device that only errors. connect now probes the transport state
and reports state/ready (and a note when not 'device').
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import AdbBackend

_NO_DEVICE = object()


class _Dev:
    def __init__(self, state: str) -> None:
        self._state = state

    def get_state(self, timeout: float | None = None) -> str:
        del timeout
        return self._state


def _backend(message: str, *, dev: Any) -> AdbBackend:
    module = type("FakeAdb", (), {})

    class AdbClient:
        def __init__(self, **kwargs: Any) -> None:
            del kwargs

        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            del endpoint, timeout
            return message

        if dev is not _NO_DEVICE:

            def device(self, serial: str) -> Any:
                del serial
                return dev

    module.AdbClient = AdbClient  # type: ignore[attr-defined]
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = module
    return backend


def test_connect_flags_an_offline_device_as_not_ready() -> None:
    payload = _backend("connected to 127.0.0.1:5555", dev=_Dev("offline")).connect(
        "127.0.0.1", 5555
    )
    assert payload["connected"] is True
    assert payload["state"] == "offline"
    assert payload["ready"] is False
    assert "note" in payload
    assert "offline" in payload["note"]


def test_connect_flags_an_unauthorized_device_as_not_ready() -> None:
    payload = _backend(
        "connected to 127.0.0.1:5555", dev=_Dev("unauthorized")
    ).connect("127.0.0.1", 5555)
    assert payload["connected"] is True
    assert payload["state"] == "unauthorized"
    assert payload["ready"] is False
    assert "unauthorized" in payload["note"]


def test_connect_marks_a_usable_device_ready_without_a_note() -> None:
    payload = _backend("connected to 127.0.0.1:5555", dev=_Dev("device")).connect(
        "127.0.0.1", 5555
    )
    assert payload["connected"] is True
    assert payload["state"] == "device"
    assert payload["ready"] is True
    assert "note" not in payload


def test_connect_omits_state_when_the_probe_is_unavailable() -> None:
    payload = _backend("connected to 127.0.0.1:5555", dev=_NO_DEVICE).connect(
        "127.0.0.1", 5555
    )
    assert payload["connected"] is True
    assert "state" not in payload
    assert "ready" not in payload
    assert "note" not in payload


def test_a_refused_connect_never_probes_or_marks_ready() -> None:
    payload = _backend(
        "unable to connect to 127.0.0.1:5555", dev=_Dev("device")
    ).connect("127.0.0.1", 5555)
    assert payload["connected"] is False
    assert "state" not in payload
    assert "ready" not in payload


def test_connect_survives_a_probe_that_raises() -> None:
    class _Boom:
        def get_state(self, timeout: float | None = None) -> str:
            del timeout
            raise RuntimeError("adb server went away")

    payload = _backend("connected to 127.0.0.1:5555", dev=_Boom()).connect(
        "127.0.0.1", 5555
    )
    assert payload["connected"] is True
    assert "state" not in payload
    assert "ready" not in payload


def test_connect_shape_matches_the_documented_fields() -> None:
    payload = _backend("connected to 127.0.0.1:5555", dev=_Dev("device")).connect(
        "127.0.0.1", 5555
    )
    assert payload == {
        "endpoint": "127.0.0.1:5555",
        "result": "connected to 127.0.0.1:5555",
        "connected": True,
        "state": "device",
        "ready": True,
    }
