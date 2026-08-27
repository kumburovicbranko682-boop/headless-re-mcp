"""Local frida ops must wrap a script-phase failure as a FridaError.

``_attach_local`` already converts an attach failure, and the device-aware
``_java_device`` / ``hook_template_device`` paths convert the
``create_script`` / ``load`` / ``exports_sync`` phase too. The local
``modules`` / ``exports`` / ``memory_read`` / ``hook_template`` paths used to
let frida's own exceptions (an ``RPCException``, or the ``Java is not defined``
script-eval error the android hooks raise on a non-ART target) escape
unwrapped. A non-``FridaError`` reaches the service's ``BaseException`` arm and
reads back as an ``internal_error`` incident rather than the ``backend_error``
envelope the android-hook docstring promises for exactly that case.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _RawFridaError(Exception):
    """Stands in for frida.core.RPCException / InvalidOperationError."""


class _FailingScript:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def load(self) -> None:
        raise self._exc

    @property
    def exports_sync(self) -> object:  # pragma: no cover - load raises first
        raise AssertionError("exports_sync must not be reached after a load failure")


class _FailingSession:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.detached = False

    def create_script(self, source: str) -> _FailingScript:
        del source
        return _FailingScript(self._exc)

    def detach(self) -> None:
        self.detached = True


def _client_that_raises_on_load(exc: Exception) -> tuple[FridaClient, _FailingSession]:
    session = _FailingSession(exc)

    class _Frida:
        def attach(self, pid: int, **kwargs: object) -> _FailingSession:
            del pid, kwargs
            return session

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    return client, session


_LOCAL_CALLS = {
    "modules": lambda c: c.modules(1, allowed_pid=1),
    "exports": lambda c: c.exports(1, "libc.so", allowed_pid=1),
    "memory_read": lambda c: c.memory_read(1, 0x1000, 16, allowed_pid=1),
    "hook_template": lambda c: c.hook_template(
        1, "android_ssl_unpin", allowed_pid=1, timeout=2.0
    ),
}


@pytest.mark.parametrize("name", sorted(_LOCAL_CALLS))
def test_local_script_load_failure_reads_as_backend_error(name: str) -> None:
    client, session = _client_that_raises_on_load(
        _RawFridaError("script eval failed: ReferenceError: Java is not defined")
    )
    with pytest.raises(FridaError) as caught:
        _LOCAL_CALLS[name](client)
    assert caught.value.code == "backend_error"
    # The session is always detached, even on the failure path, so a failed
    # probe never leaves an agent resident in the target.
    assert session.detached is True


@pytest.mark.parametrize("name", sorted(_LOCAL_CALLS))
def test_local_script_timeout_stays_retryable_timeout(name: str) -> None:
    """A transport stall named 'timeout' keeps the retryable timeout code.

    service_frida._as_rpc marks only code == "timeout" retryable, so a stall
    mapped to backend_error would turn a transient device hiccup into a
    permanent failure for an agent that retries on it.
    """
    client, _ = _client_that_raises_on_load(TimeoutError("frida transport timed out"))
    with pytest.raises(FridaError) as caught:
        _LOCAL_CALLS[name](client)
    assert caught.value.code == "timeout"
