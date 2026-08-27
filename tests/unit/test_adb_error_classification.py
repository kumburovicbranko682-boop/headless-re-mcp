"""Every adb op must classify a server/device failure, not leak a raw exception.

adbutils raises broad, version-dependent types (bare OSError, socket timeouts,
its own AdbError). Each AdbBackend op wraps its call in the same shape: an
AdbError passes through, a timeout (recognised by _is_timeout) becomes code
``timeout`` with the "adb timed out after Ns" message, and anything else
becomes the op-appropriate code -- backend_error for "cannot reach the server",
not_found for "no such device". This is the adb twin of the timeout/backend
classification pinned for frida, jsre, jadx, apktool and ghidra; without it a
timed-out adb call would surface as an internal_error incident ("file a bug")
instead of the honest "the device/server did not answer in time".

Only the happy shapes (list_devices row shaping, transfers) and _is_timeout's
callers were exercised; the classification arms themselves -- and _is_timeout's
own recognition rule -- had no test. None of this needs adbutils or a device:
_client is driven with a fake adbutils module whose AdbClient raises, and the
device/list ops are driven with a fake client (the _backend_with_client seam
the shaping tests use) whose method raises.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError, _is_timeout


class _AdbServerTimeout(Exception):
    """A driver exception whose *name* carries the timeout signal."""


class TestIsTimeout:
    @pytest.mark.parametrize(
        "exc",
        [
            TimeoutError("read timed out"),
            _AdbServerTimeout("no message signal, name only"),
            RuntimeError("the operation timed out waiting for the transport"),
            OSError("Operation timed out"),
        ],
    )
    def test_recognises_a_timeout_by_type_name_or_message(self, exc: BaseException) -> None:
        assert _is_timeout(exc) is True

    @pytest.mark.parametrize(
        "exc",
        [
            RuntimeError("connection refused"),
            OSError("broken pipe"),
            ValueError("device offline"),
        ],
    )
    def test_does_not_misread_an_unrelated_failure_as_a_timeout(
        self, exc: BaseException
    ) -> None:
        assert _is_timeout(exc) is False


class _RaisingAdbutils:
    """A fake adbutils module whose AdbClient(**kwargs) always raises."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def AdbClient(self, **kwargs: Any) -> Any:  # noqa: N802 - mirror adbutils' name
        raise self._exc


class _OldAdbutils:
    """AdbClient predating the socket_timeout kwarg: the first call raises
    TypeError, and _client must retry without it rather than fail."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def AdbClient(self, *, host: str, port: int) -> Any:  # noqa: N802
        self.calls.append({"host": host, "port": port})
        return ("client", host, port)


def _backend_with_adbutils(module: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = module
    return backend


class TestClientClassification:
    def test_a_server_timeout_becomes_code_timeout(self) -> None:
        backend = _backend_with_adbutils(_RaisingAdbutils(TimeoutError("read timed out")))
        with pytest.raises(AdbError) as caught:
            backend._client()
        assert caught.value.code == "timeout"
        assert "adb timed out after" in caught.value.message

    def test_an_unreachable_server_becomes_backend_error(self) -> None:
        backend = _backend_with_adbutils(_RaisingAdbutils(RuntimeError("connection refused")))
        with pytest.raises(AdbError) as caught:
            backend._client()
        assert caught.value.code == "backend_error"
        assert "cannot reach adb server" in caught.value.message

    def test_capability_unavailable_when_adbutils_is_absent(self) -> None:
        backend = AdbBackend()
        backend._available = False
        backend._adbutils = None
        with pytest.raises(AdbError) as caught:
            backend._client()
        assert caught.value.code == "capability_unavailable"

    def test_the_socket_timeout_kwarg_is_optional_across_adbutils_versions(self) -> None:
        """The TypeError fallback: an older AdbClient without socket_timeout must
        still yield a client, retried without the kwarg -- not read as a failure."""
        old = _OldAdbutils()
        backend = _backend_with_adbutils(old)
        client = backend._client()
        assert client[0] == "client"
        # One attempt with the kwarg (raised TypeError), one without (succeeded).
        assert old.calls == [{"host": old.calls[0]["host"], "port": old.calls[0]["port"]}]


class _RaisingClient:
    """A fake AdbClient whose device()/list() raise a scripted exception."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def device(self, serial: str | None = None) -> Any:
        raise self._exc

    def list(self) -> Any:
        raise self._exc


def _backend_with_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: client  # type: ignore[method-assign]
    return backend


class TestDeviceClassification:
    def test_a_transport_timeout_becomes_code_timeout(self) -> None:
        backend = _backend_with_client(_RaisingClient(TimeoutError("transport timed out")))
        with pytest.raises(AdbError) as caught:
            backend._device("emulator-5554")
        assert caught.value.code == "timeout"
        assert "adb timed out after" in caught.value.message

    def test_a_generic_device_failure_becomes_not_found(self) -> None:
        backend = _backend_with_client(_RaisingClient(RuntimeError("device offline")))
        with pytest.raises(AdbError) as caught:
            backend._device("emulator-5554")
        assert caught.value.code == "not_found"
        assert caught.value.details.get("serial") == "emulator-5554"

    def test_an_invalid_serial_is_refused_before_the_client(self) -> None:
        """_check_serial runs inside _device; a hostile serial is invalid_params,
        never a device lookup."""
        backend = _backend_with_client(_RaisingClient(RuntimeError("unreached")))
        with pytest.raises(AdbError) as caught:
            backend._device("emulator 5554; rm -rf /")
        assert caught.value.code == "invalid_params"


class TestListDevicesClassification:
    def test_a_probe_timeout_becomes_code_timeout(self) -> None:
        backend = _backend_with_client(_RaisingClient(TimeoutError("probe timed out")))
        with pytest.raises(AdbError) as caught:
            backend.list_devices()
        assert caught.value.code == "timeout"
        assert "adb timed out after" in caught.value.message

    def test_a_generic_probe_failure_becomes_backend_error(self) -> None:
        backend = _backend_with_client(_RaisingClient(RuntimeError("server died")))
        with pytest.raises(AdbError) as caught:
            backend.list_devices()
        assert caught.value.code == "backend_error"
        assert "failed to list devices" in caught.value.message
