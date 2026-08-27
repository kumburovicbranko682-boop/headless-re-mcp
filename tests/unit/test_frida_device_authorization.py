"""frida.* device tools must enforce the connect-then-target boundary.

The device model's whole safety story is "explicit, bounded target": a session
must connect a frida device before it can enumerate or spawn on it, and the
Java tools may only touch a pid the session itself spawned/attached. The
closed-session guards are pinned in test_frida_closed_session; the other half
-- an *open* session that simply never connected, and an authorized session
asked to act with no spawned pid -- had no service-layer coverage.

Both refusals run before FridaClient is ever constructed (_frida_auth checks
the session metadata; _last_pid checks the authorized pid list), so this holds
with frida absent and needs no device. FridaClient is monkeypatched to a
sentinel that raises if instantiated, which turns "the backend was never
reached" into an assertion rather than an assumption -- a regression that
moved the auth check after the client call would construct the sentinel and
fail loudly instead of quietly talking to a device the session never
authorized.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _ExplodingFrida:
    """Stand-in for FridaClient that must never be constructed on these paths."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("FridaClient was constructed before the auth check")


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AnalysisService:
    monkeypatch.setattr("headless_re_mcp.core.service_frida.FridaClient", _ExplodingFrida)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _open_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def test_device_tools_refuse_a_session_that_never_connected_a_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No frida_authorized metadata means no device was connected; every tool
    that acts on the device must stop at _frida_auth with invalid_state,
    pointing the caller at frida.device.connect, before any FridaClient."""
    service = _service(tmp_path, monkeypatch)
    try:
        session_id = _open_session(service, tmp_path)
        calls: dict[str, Callable[[], Result[JsonObject]]] = {
            "frida_applications": lambda: service.frida_applications(session_id),
            "frida_spawn": lambda: service.frida_spawn(session_id, "com.example.app"),
            "frida_java_classes": lambda: service.frida_java_classes(session_id),
            "frida_java_methods": lambda: service.frida_java_methods(session_id, "Lcom/example/A;"),
        }
        for name, call in calls.items():
            result = call()
            assert not result.ok, f"{name} ran without a connected device"
            assert result.error is not None, name
            assert result.error.code == "invalid_state", f"{name}: {result.error.code}"
            assert "frida.device.connect" in result.error.message, name
    finally:
        service.close_all()


def test_java_tools_refuse_when_no_pid_has_been_spawned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A connected session with an empty pid list, asked for the default pid
    (pid=0), must refuse with 'call frida.spawn first': the Java tools default
    to the most recently spawned pid, and there is none. _last_pid raises
    before the client call, so the sentinel is never constructed."""
    service = _service(tmp_path, monkeypatch)
    try:
        session_id = _open_session(service, tmp_path)
        # Authorize a device but spawn nothing -- the exact state after a bare
        # frida.device.connect.
        service.registry.update_metadata(
            session_id,
            {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}},
        )
        for call in (
            lambda: service.frida_java_classes(session_id),
            lambda: service.frida_java_methods(session_id, "Lcom/example/A;"),
        ):
            result = call()
            assert not result.ok
            assert result.error is not None
            assert result.error.code == "invalid_state"
            assert "frida.spawn" in result.error.message
    finally:
        service.close_all()
