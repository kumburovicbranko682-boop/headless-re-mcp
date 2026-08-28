"""Native frida reads (modules/exports/imports/memory) on an authorized device.

Before this, frida.modules/exports/imports/memory.read only ever attached to the
local process (the PE debuggee path), so once a session bound a USB/remote device
and spawned an app, enumerating that process's native modules or reading its
memory was impossible -- the first native step on an Android target. These cover
the device-aware backend methods and the service routing that picks them.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _NativeApi:
    """Agent stub: filter first, then honor the caller's cap (limit or limit+1)."""

    def modules(self, name_filter: str, limit: int) -> dict[str, Any]:
        rows = [
            {"name": f"m{index}", "base": "0x1", "size": 1, "path": ""}
            for index in range(25)
        ]
        if name_filter:
            rows = [row for row in rows if name_filter in row["name"]]
        return {"modules": rows[: max(0, int(limit))], "total": len(rows)}

    def exports(self, name: str, name_filter: str, count: int) -> dict[str, Any]:
        rows = [
            {"name": f"e{index}", "address": "0x2", "type": "function"}
            for index in range(25)
        ]
        if name_filter:
            rows = [row for row in rows if name_filter in row["name"]]
        return {"found": True, "module": name, "base": "0x1", "exports": rows[: int(count)]}

    def imports(self, name: str, name_filter: str, count: int) -> dict[str, Any]:
        rows = [
            {"name": f"i{index}", "type": "function", "module": "libc.so", "address": "0x3"}
            for index in range(25)
        ]
        if name_filter:
            rows = [row for row in rows if name_filter in row["name"]]
        return {"found": True, "module": name, "base": "0x1", "imports": rows[: int(count)]}

    def read(self, address: int, size: int) -> list[int]:
        del address
        return [0xAB] * int(size)


class _NativeScript:
    def __init__(self, api: _NativeApi) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _NativeSession:
    def __init__(self, api: _NativeApi) -> None:
        self._api = api

    def create_script(self, source: str) -> _NativeScript:
        del source
        return _NativeScript(self._api)

    def detach(self) -> None:
        return None


class _NativeDevice:
    def __init__(self, api: _NativeApi, attached: list[int]) -> None:
        self._api = api
        self._attached = attached

    def attach(self, pid: int) -> _NativeSession:
        self._attached.append(pid)
        return _NativeSession(self._api)


def _device_client(api: _NativeApi, attached: list[int]) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()  # only _authorize inspects it (must be non-None)
    client._resolve_device = lambda device_id: _NativeDevice(api, attached)  # type: ignore[method-assign]
    return client


def test_modules_device_enumerates_on_the_authorized_device_pid() -> None:
    attached: list[int] = []
    payload = _device_client(_NativeApi(), attached).modules_device(
        "usb", 4242, allowed_pids={4242}, limit=10
    )
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    assert attached == [4242]


def test_exports_device_name_filter_finds_a_symbol_past_the_cap() -> None:
    payload = _device_client(_NativeApi(), []).exports_device(
        "usb", 4242, "libssl.so", allowed_pids={4242}, limit=64, name_filter="e2"
    )
    assert {row["name"] for row in payload["exports"]} == {
        "e2",
        "e20",
        "e21",
        "e22",
        "e23",
        "e24",
    }
    assert payload["module"] == "libssl.so"
    assert payload["has_more"] is False


def test_imports_device_pages_and_names_the_providing_module() -> None:
    payload = _device_client(_NativeApi(), []).imports_device(
        "usb", 4242, "libtarget.so", allowed_pids={4242}, limit=10
    )
    assert payload["found"] is True
    assert payload["count"] == 10
    assert payload["has_more"] is True
    assert payload["imports"][0]["module"] == "libc.so"


def test_imports_device_requires_a_module_name() -> None:
    with pytest.raises(FridaError) as info:
        _device_client(_NativeApi(), []).imports_device(
            "usb", 4242, "  ", allowed_pids={4242}
        )
    assert info.value.code == "invalid_params"


def test_memory_read_device_returns_hex() -> None:
    payload = _device_client(_NativeApi(), []).memory_read_device(
        "usb", 4242, 0x1000, 4, allowed_pids={4242}
    )
    assert payload["data"] == "abababab"
    assert payload["encoding"] == "hex"
    assert payload["address"] == 0x1000
    assert payload["size"] == 4


@pytest.mark.parametrize("address", [-1, 2**64, 4096.0, "0x1000", True])
def test_memory_read_device_rejects_a_bad_address_before_attach(address: Any) -> None:
    attached: list[int] = []
    with pytest.raises(FridaError) as info:
        _device_client(_NativeApi(), attached).memory_read_device(
            "usb", 4242, address, 4, allowed_pids={4242}
        )
    assert info.value.code == "invalid_params"
    assert attached == []


def test_modules_device_refuses_a_pid_outside_the_authorized_set() -> None:
    """Authorization is checked before the device is even resolved."""
    resolved: list[str] = []
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: resolved.append(device_id)  # type: ignore[method-assign]
    with pytest.raises(FridaError) as info:
        client.modules_device("usb", 999, allowed_pids={4242})
    assert info.value.code == "permission_denied"
    assert resolved == []


def test_modules_device_times_out_and_detaches_the_probe() -> None:
    """A wedged RPC on the device path must not park a worker forever."""
    state = {"detached": False}

    class _HangApi:
        def modules(self, name_filter: str, limit: int) -> dict[str, Any]:
            del name_filter, limit
            time.sleep(10)
            return {"modules": [], "total": 0}

    class _HangScript:
        exports_sync = _HangApi()

        def load(self) -> None:
            return None

    class _HangSession:
        def create_script(self, source: str) -> _HangScript:
            del source
            return _HangScript()

        def detach(self) -> None:
            state["detached"] = True

    class _HangDevice:
        def attach(self, pid: int) -> _HangSession:
            del pid
            return _HangSession()

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _HangDevice()  # type: ignore[method-assign]
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.modules_device("usb", 4242, allowed_pids={4242}, timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"
    assert state["detached"] is True


# --------------------------------------------------------------------------
# Service routing: a session with a connected device reads that device pid;
# without one it falls back to the local debuggee (unchanged behavior).
# --------------------------------------------------------------------------


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _RoutingClient:
    calls: list[tuple[Any, ...]] = []

    def modules_device(
        self,
        device_id: str | None,
        pid: int,
        *,
        allowed_pids: Any,
        limit: int = 64,
        name_filter: str = "",
    ) -> dict[str, Any]:
        del limit, name_filter
        _RoutingClient.calls.append(("modules_device", device_id, pid, list(allowed_pids)))
        return {"modules": [], "count": 0, "total": 0, "has_more": False}

    def modules(
        self, pid: int, *, allowed_pid: int, limit: int = 64, name_filter: str = ""
    ) -> dict[str, Any]:
        del limit, name_filter
        _RoutingClient.calls.append(("modules", pid, allowed_pid))
        return {"modules": [], "count": 0, "total": 0, "has_more": False}


def test_frida_modules_routes_to_the_device_when_authorized(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _RoutingClient.calls = []
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda: _RoutingClient()
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        service.registry.update_metadata(
            session_id,
            {"frida_authorized": {"device_id": "ABCD", "pids": [100, 4242], "packages": ["com.x"]}},
        )
        result = service.frida_modules(session_id, limit=10)
        assert result.ok, result.error
        assert _RoutingClient.calls == [("modules_device", "ABCD", 4242, [100, 4242])]
    finally:
        service.close_all()


def test_frida_modules_without_a_device_stays_on_the_debuggee_path(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """No connected device and no debuggee -> invalid_state, and it never
    reaches the device method. The local path is unchanged."""
    _RoutingClient.calls = []
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda: _RoutingClient()
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.frida_modules(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
        assert _RoutingClient.calls == []
    finally:
        service.close_all()
