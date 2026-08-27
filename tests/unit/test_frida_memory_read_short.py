"""frida.memory.read must disclose a short or failed read, not imply a full one.

frida's ``readByteArray(size)`` returns null for a range it cannot read (an
unmapped or guarded page) and can hand back fewer bytes than requested; the
enumeration script turns that into an empty or short array. Reporting the
requested ``size`` next to a shorter hex string would let a caller read past
the bytes that actually exist. The client now also reports ``bytes_read`` and,
when it falls short, a ``truncated`` flag -- so an unreadable region is never
mistaken for real data. The native runtime cannot run in CI, so a fake session
stands in for the on-device script, the way the other frida unit tests do.
"""

from __future__ import annotations

from headless_re_mcp.backends.frida.client import FridaClient


class _ReadApi:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload

    def read(self, address: int, size: int) -> list[int]:
        del address, size
        return list(self._payload)


class _ReadScript:
    def __init__(self, payload: list[int]) -> None:
        self.exports_sync = _ReadApi(payload)

    def load(self) -> None:
        return None


class _ReadSession:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload

    def create_script(self, source: str) -> _ReadScript:
        del source
        return _ReadScript(self._payload)

    def detach(self) -> None:
        return None


class _ReadFrida:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload

    def attach(self, pid: int) -> _ReadSession:
        del pid
        return _ReadSession(self._payload)


def _client(payload: list[int]) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _ReadFrida(payload)
    return client


def test_full_read_reports_bytes_read_equal_to_size_without_truncation() -> None:
    payload = _client([0xAB] * 16).memory_read(1, 0x1000, 16, allowed_pid=1)
    assert payload["size"] == 16
    assert payload["bytes_read"] == 16
    assert payload["data"] == "ab" * 16
    assert "truncated" not in payload


def test_an_unreadable_range_is_flagged_not_reported_as_a_full_read() -> None:
    # frida hands back null -> empty array when the range is unmapped/guarded.
    payload = _client([]).memory_read(1, 0x1000, 4096, allowed_pid=1)
    assert payload["size"] == 4096
    assert payload["bytes_read"] == 0
    assert payload["data"] == ""
    assert payload["truncated"] is True
    assert "note" in payload


def test_a_short_read_reports_the_actual_byte_count() -> None:
    payload = _client([1, 2, 3]).memory_read(1, 0x1000, 8, allowed_pid=1)
    assert payload["size"] == 8
    assert payload["bytes_read"] == 3
    assert payload["data"] == "010203"
    assert payload["truncated"] is True
