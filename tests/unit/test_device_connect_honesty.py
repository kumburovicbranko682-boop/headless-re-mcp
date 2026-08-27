"""device.connect must not call a refused TCP connect a success."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.core.service_device import DeviceAnalysisMixin
from headless_re_mcp.tools.device import build_device_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_device_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _backend(message: str) -> AdbBackend:
    module = type("FakeAdb", (), {})
    outer = SimpleNamespace(message=message)

    class AdbClient:
        def __init__(self, **kwargs: Any) -> None:
            del kwargs

        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            del endpoint, timeout
            return outer.message

    module.AdbClient = AdbClient  # type: ignore[attr-defined]
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = module
    return backend


def _raising_backend(exc: BaseException) -> AdbBackend:
    module = type("FakeAdb", (), {})

    class AdbClient:
        def __init__(self, **kwargs: Any) -> None:
            del kwargs

        def connect(self, endpoint: str, timeout: float | None = None) -> str:
            del endpoint, timeout
            raise exc

    module.AdbClient = AdbClient  # type: ignore[attr-defined]
    backend = AdbBackend()
    backend._available = True
    backend._adbutils = module
    return backend


class _Harness(DeviceAnalysisMixin):
    def __init__(self, backend: AdbBackend) -> None:
        self.settings = SimpleNamespace(adb=None)
        self._adb_backend = backend


def test_a_refused_adb_connect_is_not_an_ok_envelope() -> None:
    """adbutils returns a string; the client used to wrap it as success.

    Measured against AdbBackend.connect with message
    "unable to connect to 127.0.0.1:5555": connected is False, no
    exception. DeviceAnalysisMixin then answered ok=True, error=None.
    An unattended caller that only reads the envelope then installs onto
    a device that is not there.
    """
    backend = _backend("unable to connect to 127.0.0.1:5555")
    payload = backend.connect("127.0.0.1", 5555)
    assert payload["connected"] is False
    assert payload["endpoint"] == "127.0.0.1:5555"
    assert "unable to connect" in str(payload["result"]).lower()

    result = _Harness(backend).device_connect("127.0.0.1", 5555)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"
    assert "unable to connect" in result.error.message.lower()


def test_an_accepted_adb_connect_stays_ok() -> None:
    backend = _backend("connected to 127.0.0.1:5555")
    result = _Harness(backend).device_connect("127.0.0.1", 5555)
    assert result.ok is True
    assert result.data is not None
    assert result.data["connected"] is True
    assert result.data["endpoint"] == "127.0.0.1:5555"
    assert "ok" not in result.data
    assert "serial" not in result.data


def test_already_connected_is_still_a_success() -> None:
    backend = _backend("already connected to 127.0.0.1:5555")
    result = _Harness(backend).device_connect("127.0.0.1", 5555)
    assert result.ok is True
    assert result.data is not None
    assert result.data["connected"] is True


def test_a_connect_timeout_is_reported_as_timeout_not_backend_error() -> None:
    """connect passes timeout=10.0 but skipped the _is_timeout mapping.

    adbutils raises AdbTimeout when the connect deadline elapses. Every
    sibling adb call maps a timeout to code "timeout"; connect alone flattened
    it to backend_error. A caller retries a timeout -- a slow emulator that is
    still coming up -- but treats backend_error as a hard fault and gives up.
    Measured: code is timeout both at the client and through the mixin.
    """
    backend = _raising_backend(TimeoutError("connect timed out"))
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 5555)
    assert caught.value.code == "timeout"

    result = _Harness(backend).device_connect("127.0.0.1", 5555)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


def test_a_non_timeout_connect_failure_stays_backend_error() -> None:
    backend = _raising_backend(ValueError("connection refused"))
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", 5555)
    assert caught.value.code == "backend_error"


def test_device_connect_names_connected_not_ok() -> None:
    doc = _tool_docstring("device.connect")
    assert "Answers with endpoint" in doc
    assert "connected" in doc
    assert "result" in doc
    assert "envelope failure" in doc.lower() or "not an ok envelope" in doc.lower()
