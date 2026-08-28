"""Local frida ops must file a backend failure as backend_error, not incident.

modules/exports/memory.read attach, run one RPC, and detach. Only the attach
was wrapped, so a frida error from the RPC -- the common one is memory.read on
an unmapped address, where frida raises "access violation accessing 0x.." --
propagated raw. ``_failure`` then filed it under ``internal_error`` and minted
an incident, while the device-side java/hook paths already classified the same
frida failures as ``backend_error``. These pin the local path to that contract
and confirm the session is still detached on the failure path.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _RaisingExports:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def modules(self, limit: int) -> Any:
        del limit
        raise self._exc

    def exports(self, name: str, count: int) -> Any:
        del name, count
        raise self._exc

    def read(self, address: int, size: int) -> Any:
        del address, size
        raise self._exc


class _RaisingScript:
    def __init__(self, exc: BaseException) -> None:
        self.exports_sync = _RaisingExports(exc)

    def load(self) -> None:
        return None


class _RaisingSession:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.detached = False

    def create_script(self, source: str) -> _RaisingScript:
        del source
        return _RaisingScript(self._exc)

    def detach(self) -> None:
        self.detached = True


class _RaisingFrida:
    def __init__(self, exc: BaseException) -> None:
        self.session = _RaisingSession(exc)

    def attach(self, pid: int) -> _RaisingSession:
        del pid
        return self.session


def _client(exc: BaseException) -> tuple[FridaClient, _RaisingFrida]:
    client = FridaClient()
    client._available = True
    frida = _RaisingFrida(exc)
    client._frida = frida
    return client, frida


def test_memory_read_maps_an_access_violation_to_backend_error() -> None:
    client, frida = _client(RuntimeError("access violation accessing 0x0"))

    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x1000, 16, allowed_pid=1)

    assert caught.value.code == "backend_error"
    assert "access violation" in caught.value.message
    assert caught.value.details["pid"] == 1
    assert caught.value.details["address"] == 0x1000
    assert caught.value.details["size"] == 16
    assert frida.session.detached is True


def test_modules_maps_a_script_failure_to_backend_error() -> None:
    client, frida = _client(RuntimeError("script boom"))

    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)

    assert caught.value.code == "backend_error"
    assert caught.value.details["pid"] == 1
    assert frida.session.detached is True


def test_exports_maps_a_script_failure_to_backend_error() -> None:
    client, frida = _client(RuntimeError("enumerate boom"))

    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)

    assert caught.value.code == "backend_error"
    assert caught.value.details["module"] == "libc.so"
    assert frida.session.detached is True


def test_local_rpc_timeout_keeps_the_timeout_code() -> None:
    client, _ = _client(RuntimeError("the request timed out"))

    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x2000, 8, allowed_pid=1)

    assert caught.value.code == "timeout"


class _AttachRaisingFrida:
    """attach itself fails, before any session exists."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def attach(self, pid: int) -> Any:
        del pid
        raise self._exc


def test_local_attach_failure_is_backend_error_naming_the_pid() -> None:
    """A failed local attach is classified like the device attach path.

    _attach_local backs modules/exports/memory.read; the existing tests fail the
    RPC after attach succeeds, so the arm where frida.attach itself raises -- a
    local pid that exited between authorization and attach, or a process that
    refuses injection -- was never exercised. It must be backend_error carrying
    the pid, not the raw exception _failure would mint as an internal_error
    incident. No session was opened, so there is nothing to detach.
    """
    client = FridaClient()
    client._available = True
    client._frida = _AttachRaisingFrida(RuntimeError("unable to attach: process not found"))

    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)

    assert caught.value.code == "backend_error"
    assert "attach failed" in caught.value.message
    assert caught.value.details["pid"] == 1


def test_local_attach_timeout_keeps_the_timeout_code() -> None:
    """A local attach that outruns the deadline stays a timeout, not backend_error."""
    client = FridaClient()
    client._available = True
    client._frida = _AttachRaisingFrida(RuntimeError("the request timed out"))

    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x1000, 16, allowed_pid=1)

    assert caught.value.code == "timeout"


def test_every_op_reports_capability_unavailable_when_frida_is_absent() -> None:
    """A missing frida module must degrade, not crash, on every entry point.

    frida is a Python import, so shutil.which does not gate it and the CLI
    degradation contract cannot reach it; this is its half of that contract. The
    client guards availability at three distinct sites -- the direct check in
    attach, _require for the pid-scoped local ops, and _need for the device
    ops -- so a representative op from each must surface capability_unavailable
    ("install frida") rather than an AttributeError on the None handle, which
    _failure would file as an internal_error incident. pid == allowed_pid is
    passed so the pid-scoped ops reach the availability branch instead of
    stopping at the permission check that precedes it.
    """
    client = FridaClient()
    client._available = False
    client._frida = None

    entry_points: list[tuple[str, Callable[[], object]]] = [
        ("attach", lambda: client.attach(1, allowed_pid=1)),
        ("modules", lambda: client.modules(1, allowed_pid=1)),
        ("enumerate_devices", client.enumerate_devices),
    ]
    for label, call in entry_points:
        with pytest.raises(FridaError) as caught:
            call()
        assert caught.value.code == "capability_unavailable", label
        assert "not installed" in caught.value.message, label
