"""Frida memory.read used to call a short read the requested size."""

from __future__ import annotations

from headless_re_mcp.backends.frida.client import FridaClient


class _Exports:
    def __init__(self, blob: list[int]) -> None:
        self._blob = blob

    def read(self, address: int, size: int) -> list[int]:
        del address, size
        return self._blob


class _Script:
    def __init__(self, blob: list[int]) -> None:
        self.exports_sync = _Exports(blob)

    def load(self) -> None:
        return None


class _Session:
    def __init__(self, blob: list[int]) -> None:
        self._blob = blob

    def create_script(self, src: str) -> _Script:
        del src
        return _Script(self._blob)

    def detach(self) -> None:
        return None


class _Frida:
    def __init__(self, blob: list[int]) -> None:
        self._blob = blob

    def attach(self, pid: int) -> _Session:
        del pid
        return _Session(self._blob)


class TestFridaMemoryReadSaysWhenItStopped:
    """A short read used to look like the whole requested range.

    Measured: asked 16, size field 16, data 3 bytes, no truncated -- so a
    caller that trusts size treats the slice as every byte it asked for.
    """

    def _client(self, blob: list[int]) -> FridaClient:
        client = FridaClient()
        client._frida = _Frida(blob)
        client._available = True
        return client

    def test_a_short_read_is_reported(self) -> None:
        result = self._client([1, 2, 3]).memory_read(7, 0x1000, 16, allowed_pid=7)
        assert result["size"] == 3
        assert result["data"] == "010203"
        assert result["truncated"] is True

    def test_a_full_read_is_complete(self) -> None:
        blob = list(range(16))
        result = self._client(blob).memory_read(7, 0x1000, 16, allowed_pid=7)
        assert result["size"] == 16
        assert "truncated" not in result
