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


def test_device_connect_names_connected_not_ok() -> None:
    doc = _tool_docstring("device.connect")
    assert "Answers with endpoint" in doc
    assert "connected" in doc
    assert "result" in doc
    assert "envelope failure" in doc.lower() or "not an ok envelope" in doc.lower()


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 999999])
def test_connect_rejects_a_bad_port_before_the_capability_gate(bad_port: int) -> None:
    """A bad port must fail as invalid_params even when adbutils is absent.

    connect() used to call _client() -- which raises capability_unavailable when
    adbutils is not installed -- before validating the port, so a bad port on a
    host without adbutils surfaced as capability_unavailable rather than the
    invalid_params it was. The port and endpoint checks now run first, matching
    proxy.start and the fail-fast convention: with _available forced False (so
    the capability gate would fire if reached), a bad port still fails precisely.
    """
    backend = AdbBackend()
    backend._available = False
    with pytest.raises(AdbError) as caught:
        backend.connect("127.0.0.1", bad_port)
    assert caught.value.code == "invalid_params"
    assert caught.value.details["port"] == bad_port
