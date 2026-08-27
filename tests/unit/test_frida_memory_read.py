"""frida.memory.read must use the NativePointer API and report hex bytes."""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida import client as frida_client
from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _ReadApi:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def read(self, address: int, size: int) -> list[int]:
        self.calls.append((int(address), int(size)))
        return list(range(int(size)))


class _ReadScript:
    exports_sync = _ReadApi()

    def load(self) -> None:
        return None


class _ReadSession:
    def create_script(self, source: str) -> _ReadScript:
        del source
        return _ReadScript()

    def detach(self) -> None:
        return None


class _ReadFrida:
    def attach(self, pid: int) -> _ReadSession:
        del pid
        return _ReadSession()


def test_frida_memory_read_returns_hex_encoded_bytes() -> None:
    """A successful read hands back size bytes as hex, echoing the request.

    Measured: 4 bytes -> data '00010203', encoding hex, and the address/size
    the caller asked for. An agent decoding data as anything but hex, or
    reading a different width than it requested, would misread the target.
    """
    client = FridaClient()
    client._available = True
    client._frida = _ReadFrida()
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["address"] == 0x1000
    assert payload["size"] == 4
    assert payload["encoding"] == "hex"
    assert payload["data"] == "00010203"


def test_frida_memory_read_rejects_out_of_range_sizes() -> None:
    """The read width is bounded before any attach happens."""
    client = FridaClient()
    client._available = True
    client._frida = _ReadFrida()
    for bad in (0, -1, 256 * 1024 + 1):
        with pytest.raises(FridaError) as caught:
            client.memory_read(1, 0x1000, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_enum_script_reads_via_native_pointer_not_removed_global() -> None:
    """Guard the read against the API break that silently disabled it.

    frida 16.6 deprecated and 17 removed the top-level ``Memory.readByteArray``
    helper; the global form raises ``TypeError: not a function`` at call time,
    so a probe that used it returned backend_error on every current runtime
    while still passing every mock-based test. Pin the NativePointer form so a
    regression fails here instead of only against a live frida 17 process.
    """
    script = frida_client._ENUM_SCRIPT
    assert "ptr(address).readByteArray(" in script
    assert "Memory.readByteArray(" not in script
