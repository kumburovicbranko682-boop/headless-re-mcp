"""device.forwards lists adb tunnels and keeps unreadable reverses distinct from none."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import _MAX_FORWARDS, AdbBackend, AdbError


@dataclass
class _Fwd:
    serial: str
    local: str
    remote: str


@dataclass
class _Rev:
    remote: str
    local: str


class _Device:
    def __init__(self, forwards: list[Any], reverses: list[Any] | None) -> None:
        self._forwards = forwards
        self._reverses = reverses

    def forward_list(self) -> list[Any]:
        return self._forwards

    # reverse_list is attached per-test so the "method absent" case can drop it.
    if False:  # pragma: no cover - documents the optional method

        def reverse_list(self) -> list[Any]:  # noqa: D401
            return []


def _backend(monkeypatch: pytest.MonkeyPatch, device: _Device) -> AdbBackend:
    backend = AdbBackend()
    monkeypatch.setattr(backend, "_device", lambda serial: device)
    return backend


def test_forwards_maps_both_directions(monkeypatch: pytest.MonkeyPatch) -> None:
    device = _Device(
        forwards=[_Fwd("emulator-5554", "tcp:27042", "tcp:27042")],
        reverses=[_Rev("tcp:8080", "tcp:9090")],
    )
    device.reverse_list = lambda: device._reverses  # type: ignore[attr-defined]
    payload = _backend(monkeypatch, device).forwards("emulator-5554")
    assert payload["forwards"] == [{"local": "tcp:27042", "remote": "tcp:27042"}]
    assert payload["reverses"] == [{"local": "tcp:9090", "remote": "tcp:8080"}]
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_forwards_omits_reverses_when_the_build_cannot_read_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No reverse_list method: the key is absent, not an empty list.

    An empty reverses would read as "no reverse tunnels"; omitting it says
    "this adb build could not tell", which is the honest distinction.
    """
    device = _Device(forwards=[_Fwd("s", "tcp:1", "tcp:2")], reverses=None)
    # Ensure the attribute truly is not callable on this device.
    assert not callable(getattr(device, "reverse_list", None))
    payload = _backend(monkeypatch, device).forwards("s")
    assert "reverses" not in payload
    assert payload["count"] == 1
    assert payload["has_more"] is False


def test_forwards_caps_each_direction_and_flags_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    many = [_Fwd("s", f"tcp:{i}", f"tcp:{i}") for i in range(_MAX_FORWARDS + 5)]
    device = _Device(forwards=many, reverses=[])
    device.reverse_list = lambda: device._reverses  # type: ignore[attr-defined]
    payload = _backend(monkeypatch, device).forwards("s")
    assert len(payload["forwards"]) == _MAX_FORWARDS
    assert payload["reverses"] == []
    assert payload["has_more"] is True
    assert payload["count"] == _MAX_FORWARDS


def test_forwards_maps_a_backend_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Boom:
        def forward_list(self) -> list[Any]:
            raise RuntimeError("adb server gone")

    backend = AdbBackend()
    monkeypatch.setattr(backend, "_device", lambda serial: _Boom())
    with pytest.raises(AdbError) as caught:
        backend.forwards("s")
    assert caught.value.code == "backend_error"
