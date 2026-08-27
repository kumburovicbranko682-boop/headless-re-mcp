"""A frida runtime fault in a local script must surface as backend_error.

``_attach_local`` already maps its own failures to a ``FridaError``, but the
``create_script`` / ``load`` / ``exports_sync`` calls that follow on the local
path (``modules`` / ``exports`` / ``memory.read`` / ``hook.template``) ran in a
bare try/finally. A raw frida fault there escaped the client, reached the
service envelope's ``except BaseException``, and was filed as an internal_error
with a logged incident -- casting a backend result as a server defect.

Reading an unmapped address is the everyday case: probing memory that is not
mapped is a normal outcome of the tool, and it raises inside frida. These pin
that such faults now become a structured ``backend_error`` (or ``timeout`` when
the fault is a frida deadline), with the session still detached.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _FaultingApi:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def modules(self, limit: int) -> object:
        del limit
        raise self._exc

    def exports(self, name: str, count: int) -> object:
        del name, count
        raise self._exc

    def read(self, address: int, size: int) -> object:
        del address, size
        raise self._exc


class _FaultingScript:
    def __init__(self, exc: BaseException, *, fail_load: bool = False) -> None:
        self.exports_sync = _FaultingApi(exc)
        self._exc = exc
        self._fail_load = fail_load

    def load(self) -> None:
        if self._fail_load:
            raise self._exc


class _FaultingSession:
    def __init__(self, exc: BaseException, *, fail_load: bool = False) -> None:
        self._exc = exc
        self._fail_load = fail_load
        self.detached = False

    def create_script(self, source: str) -> _FaultingScript:
        del source
        return _FaultingScript(self._exc, fail_load=self._fail_load)

    def detach(self) -> None:
        self.detached = True


class _FaultingFrida:
    def __init__(self, session: _FaultingSession) -> None:
        self._session = session

    def attach(self, pid: int) -> _FaultingSession:
        del pid
        return self._session


def _client(session: _FaultingSession) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _FaultingFrida(session)
    return client


def test_memory_read_of_an_unmapped_address_is_a_backend_error_not_an_incident() -> None:
    session = _FaultingSession(RuntimeError("access violation accessing 0x41414141"))
    client = _client(session)
    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x41414141, 16, allowed_pid=1)
    assert caught.value.code == "backend_error"
    assert "access violation" in caught.value.message
    assert session.detached is True


def test_a_frida_rpc_timeout_in_a_read_maps_to_timeout() -> None:
    session = _FaultingSession(TimeoutError("frida rpc timed out"))
    client = _client(session)
    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x1000, 16, allowed_pid=1)
    assert caught.value.code == "timeout"
    assert session.detached is True


def test_modules_enumeration_fault_is_a_backend_error() -> None:
    session = _FaultingSession(RuntimeError("script terminated"))
    client = _client(session)
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1, limit=8)
    assert caught.value.code == "backend_error"
    assert session.detached is True


def test_exports_enumeration_fault_is_a_backend_error() -> None:
    session = _FaultingSession(RuntimeError("module walk failed"))
    client = _client(session)
    with pytest.raises(FridaError) as caught:
        client.exports(1, "ntdll.dll", allowed_pid=1, limit=8)
    assert caught.value.code == "backend_error"
    assert session.detached is True


def test_a_local_hook_template_load_fault_is_a_backend_error() -> None:
    session = _FaultingSession(RuntimeError("script load rejected"), fail_load=True)
    client = _client(session)
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "backend_error"
    assert session.detached is True
