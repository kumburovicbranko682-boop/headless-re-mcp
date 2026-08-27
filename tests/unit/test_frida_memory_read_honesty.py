from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _FakeExports:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload

    def read(self, _address: int, _size: int) -> list[int]:
        # Stand in for the injected agent's rpc export: return whatever byte
        # array the test scripted, regardless of the size asked for. A real
        # readByteArray returns null (-> empty here) for an unreadable range.
        return list(self._payload)


class _FakeScript:
    def __init__(self, payload: list[int]) -> None:
        self.exports_sync = _FakeExports(payload)

    def load(self) -> None:
        return None


class _FakeSession:
    def __init__(self, payload: list[int]) -> None:
        self._payload = payload
        self.detached = False

    def create_script(self, _source: str) -> _FakeScript:
        return _FakeScript(self._payload)

    def detach(self) -> None:
        self.detached = True


def _client_returning(
    payload: list[int], monkeypatch: pytest.MonkeyPatch
) -> tuple[FridaClient, _FakeSession]:
    client = FridaClient()
    # Present the capability without a real frida runtime, and hand memory_read
    # a scripted session so the read payload is under the test's control.
    client._available = True  # noqa: SLF001
    client._frida = object()  # noqa: SLF001
    session = _FakeSession(payload)
    monkeypatch.setattr(client, "_attach_local", lambda pid, **_: session)  # noqa: SLF001
    return client, session


def test_a_full_read_returns_the_bytes_as_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    client, session = _client_returning([0xDE, 0xAD, 0xBE, 0xEF], monkeypatch)

    result = client.memory_read(4242, 0x1000, 4, allowed_pid=4242)

    assert result["data"] == "deadbeef"
    assert result["size"] == 4
    assert session.detached is True


def test_a_short_read_is_reported_as_a_failure_not_a_padded_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreadable range comes back short; it must not read as size bytes."""
    client, session = _client_returning([0x01, 0x02], monkeypatch)

    with pytest.raises(FridaError) as info:
        client.memory_read(4242, 0x1000, 16, allowed_pid=4242)

    assert info.value.code == "backend_error"
    assert info.value.details["requested"] == 16
    assert info.value.details["returned"] == 2
    # The session is still released even though the read failed.
    assert session.detached is True


def test_an_empty_read_is_reported_as_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = _client_returning([], monkeypatch)

    with pytest.raises(FridaError) as info:
        client.memory_read(4242, 0x1000, 8, allowed_pid=4242)

    assert info.value.code == "backend_error"
    assert info.value.details["returned"] == 0
