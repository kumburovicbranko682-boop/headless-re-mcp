"""Native Frida reads (modules/exports/memory) must work on a device pid.

frida.hook.template already routed to the connected device pid; the native
reads did not, so an Android session could hook Java and inject templates but
never inspect the .so modules loaded in the app or read its process memory.
These pin the new device backend variants and the service-level dispatch that
picks them when the session has an authorized device pid.
"""

from __future__ import annotations

import types
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _EnumApi:
    def modules(self, limit: int) -> dict[str, Any]:
        del limit
        return {
            "modules": [
                {"name": f"lib{i}.so", "base": "0x1", "size": 1, "path": f"/data/lib{i}.so"}
                for i in range(25)
            ],
            "total": 25,
        }

    def exports(self, name: str, count: int) -> dict[str, Any]:
        return {
            "found": True,
            "module": name,
            "base": "0x1",
            "exports": [
                {"name": f"e{i}", "address": "0x2", "type": "function"}
                for i in range(int(count))
            ],
        }

    def read(self, address: int, size: int) -> list[int]:
        del address, size
        return [0xDE, 0xAD, 0xBE, 0xEF]


class _EnumScript:
    exports_sync = _EnumApi()

    def load(self) -> None:
        return None


class _EnumSession:
    def __init__(self) -> None:
        self.detached = False

    def create_script(self, source: str) -> _EnumScript:
        del source
        return _EnumScript()

    def detach(self) -> None:
        self.detached = True


class _EnumDevice:
    def __init__(self) -> None:
        self.session = _EnumSession()

    def attach(self, pid: int) -> _EnumSession:
        del pid
        return self.session


def _device_client() -> tuple[FridaClient, _EnumDevice]:
    client = FridaClient()
    client._available = True
    client._frida = object()
    device = _EnumDevice()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client, device


def test_modules_device_returns_the_shaped_page_and_detaches() -> None:
    client, device = _device_client()
    payload = client.modules_device("usb", 4242, allowed_pids=[4242], limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    assert payload["modules"][0]["name"].endswith(".so")
    # A probe, like every other native read: the session is gone before return.
    assert device.session.detached is True


def test_exports_device_pages_like_the_local_read() -> None:
    client, _device = _device_client()
    payload = client.exports_device("usb", 4242, "libfoo.so", allowed_pids=[4242], limit=10)
    assert payload["found"] is True
    assert payload["module"] == "libfoo.so"
    assert payload["count"] == 10
    assert payload["has_more"] is True


def test_memory_read_device_reports_bytes_returned_not_requested() -> None:
    client, _device = _device_client()
    payload = client.memory_read_device("usb", 4242, 0x1000, 16, allowed_pids=[4242])
    assert payload["requested"] == 16
    assert payload["size"] == 4
    assert payload["complete"] is False
    assert payload["data"] == "deadbeef"


def test_device_reads_refuse_a_pid_outside_the_allow_set() -> None:
    client, _device = _device_client()
    for call in (
        lambda: client.modules_device("usb", 999, allowed_pids=[7]),
        lambda: client.exports_device("usb", 999, "libc.so", allowed_pids=[7]),
        lambda: client.memory_read_device("usb", 999, 0x1000, 16, allowed_pids=[7]),
    ):
        with pytest.raises(FridaError) as info:
            call()
        assert info.value.code == "permission_denied"


def test_memory_read_device_rejects_a_bad_size() -> None:
    client, _device = _device_client()
    with pytest.raises(FridaError) as info:
        client.memory_read_device("usb", 4242, 0x1000, 0, allowed_pids=[4242])
    assert info.value.code == "invalid_params"


class _RoutingClient:
    """Records whether the service reached the device or the local variant."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def modules_device(
        self, device_id: str | None, pid: int, *, allowed_pids: Any, limit: int = 64
    ) -> dict[str, Any]:
        self.calls.append(("modules_device", device_id, pid, list(allowed_pids), limit))
        return {"modules": [], "count": 0, "total": 0, "has_more": False}

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> dict[str, Any]:
        self.calls.append(("modules_local", pid))
        return {"modules": [], "count": 0, "total": 0, "has_more": False}

    def exports_device(
        self,
        device_id: str | None,
        pid: int,
        module_name: str,
        *,
        allowed_pids: Any,
        limit: int = 64,
    ) -> dict[str, Any]:
        self.calls.append(("exports_device", device_id, pid, module_name, list(allowed_pids)))
        return {
            "found": True,
            "module": module_name,
            "base": "",
            "exports": [],
            "count": 0,
            "has_more": False,
        }

    def memory_read_device(
        self,
        device_id: str | None,
        pid: int,
        address: int,
        size: int,
        *,
        allowed_pids: Any,
    ) -> dict[str, Any]:
        self.calls.append(
            ("memory_read_device", device_id, pid, address, size, list(allowed_pids))
        )
        return {
            "address": address,
            "size": 0,
            "requested": size,
            "complete": False,
            "encoding": "hex",
            "data": "",
        }


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def test_service_routes_native_reads_to_the_authorized_device_pid(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A session holding a device auth must reach the *_device backend variants."""
    routing = _RoutingClient()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient",
        lambda *args, **kwargs: routing,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        session_id = _session(service, tmp_path)
        service.registry.update_metadata(
            session_id,
            {"frida_authorized": {"device_id": "usb", "pids": [4242], "packages": []}},
        )

        assert service.frida_modules(session_id, limit=5).ok
        assert service.frida_exports(session_id, "libssl.so", limit=5).ok
        assert service.frida_memory_read(session_id, 0x1000, 16).ok

        kinds = [call[0] for call in routing.calls]
        assert kinds == ["modules_device", "exports_device", "memory_read_device"]
        # The pid and allow-set it hands the backend are the session's own.
        assert routing.calls[0][1:4] == ("usb", 4242, [4242])
    finally:
        service.close_all()


def test_service_uses_the_local_read_without_a_device_auth(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A PE session with no device auth keeps the local single-pid path."""
    routing = _RoutingClient()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient",
        lambda *args, **kwargs: routing,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        session_id = _session(service, tmp_path)
        # No frida_authorized metadata; fake a live local debuggee so the local
        # path resolves a pid instead of failing for want of one.
        monkeypatch.setattr(
            service,
            "dynamic_state",
            lambda sid: types.SimpleNamespace(ok=True, data={"debuggee_pid": 4242}),
        )

        assert service.frida_modules(session_id).ok
        assert routing.calls[-1] == ("modules_local", 4242)
    finally:
        service.close_all()
