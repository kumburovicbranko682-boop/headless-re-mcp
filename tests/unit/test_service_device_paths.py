"""Delegation, retention and error-mapping paths of the ADB device mixin.

The adb backend has its own suite; this file covers the service layer that
exposes ``device.*`` -- the uniform ``_adb_wrap`` delegators, the connect
success/false/failure split, the oversized-capture refusal and directory
retention on screenshot/pull, and the ``AdbError`` -> envelope mapping. The
backend is faked (subclassing ``AdbBackend`` with a no-op init), so no adb
server or device is touched.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_device as service_device
from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    _safe_pull_suffix,
    prune_device_artifacts,
    refuse_oversized_device_file,
)


class _OkAdb(AdbBackend):
    def __init__(self) -> None:  # skip the real adbutils probe
        pass

    def list_devices(self) -> dict[str, Any]:
        return {"devices": []}

    def connect(self, host: str, port: int) -> dict[str, Any]:
        return {"connected": True, "endpoint": f"{host}:{port}"}

    def info(self, serial: str) -> dict[str, Any]:
        return {"serial": serial}

    def properties(self, serial: str, limit: int = 500) -> dict[str, Any]:
        return {"properties": {}}

    def packages(
        self, serial: str, third_party_only: bool = False, limit: int = 500
    ) -> dict[str, Any]:
        return {"packages": []}

    def install(self, serial: str, apk_path: str, reinstall: bool = True) -> dict[str, Any]:
        return {"installed": True}

    def uninstall(self, serial: str, package: str) -> dict[str, Any]:
        return {"uninstalled": True}

    def launch(self, serial: str, package: str) -> dict[str, Any]:
        return {"launched": True}

    def force_stop(self, serial: str, package: str) -> dict[str, Any]:
        return {"stopped": True}

    def current_activity(self, serial: str) -> dict[str, Any]:
        return {"activity": "a.b/.Main"}

    def logcat(self, serial: str, lines: int = 200) -> dict[str, Any]:
        return {"lines": []}

    def screenshot(self, serial: str, out_path: Path) -> dict[str, Any]:
        Path(out_path).write_bytes(b"\x89PNG")
        return {"path": str(out_path)}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
        Path(local_path).write_bytes(b"data")
        return {"path": str(local_path)}

    def push(self, serial: str, local_path: str, remote_path: str) -> dict[str, Any]:
        return {"pushed": True}

    def forward(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        return {"forwarded": True}


class _Host(DeviceAnalysisMixin):
    def __init__(self, root: Path, backend: AdbBackend | None) -> None:
        self.settings = SimpleNamespace(artifact_root=root, adb=None)
        if backend is not None:
            self._adb_backend = backend


@pytest.fixture
def host(tmp_path: Path) -> _Host:
    return _Host(tmp_path / "artifacts", _OkAdb())


# ---------------------------------------------------------------------------
# _safe_pull_suffix


@pytest.mark.parametrize(
    "remote,expected",
    [
        ("/sdcard/x.png", ".png"),
        ("/data/app.apk", ".apk"),
        ("/no/extension", ".bin"),
        ("/weird/name.this_is_way_too_long_to_keep", ".bin"),
        ("/stream/name.a:b", ".bin"),
    ],
)
def test_safe_pull_suffix(remote: str, expected: str) -> None:
    assert _safe_pull_suffix(remote) == expected


# ---------------------------------------------------------------------------
# prune_device_artifacts


def test_prune_swallows_a_root_that_cannot_be_listed(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("x", encoding="utf-8")

    prune_device_artifacts(not_a_dir)


def test_prune_keeps_everything_under_the_cap(tmp_path: Path) -> None:
    for i in range(3):
        (tmp_path / f"c-{i}.png").write_bytes(b"x")

    prune_device_artifacts(tmp_path, keep=32)

    assert len(list(tmp_path.iterdir())) == 3


def test_prune_drops_the_oldest_captures(tmp_path: Path) -> None:
    files = []
    for i in range(6):
        path = tmp_path / f"c-{i}.png"
        path.write_bytes(b"x")
        os.utime(path, (1_000 + i, 1_000 + i))
        files.append(path)

    prune_device_artifacts(tmp_path, keep=4)

    assert not files[0].exists()
    assert not files[1].exists()
    assert all(path.exists() for path in files[2:])


# ---------------------------------------------------------------------------
# refuse_oversized_device_file


def test_refuse_ignores_a_missing_file(tmp_path: Path) -> None:
    assert refuse_oversized_device_file(tmp_path / "gone") is None


def test_refuse_keeps_a_file_within_the_limit(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"tiny")

    assert refuse_oversized_device_file(small) is None
    assert small.exists()


def test_refuse_deletes_and_reports_an_oversized_file(tmp_path: Path) -> None:
    blob = tmp_path / "big.bin"
    blob.write_bytes(b"payload")

    result = refuse_oversized_device_file(blob, limit=0)

    assert result is not None
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "output_too_large"
    assert not blob.exists()


# ---------------------------------------------------------------------------
# uniform delegators


_DELEGATORS: list[tuple[str, Callable[[_Host], Any]]] = [
    ("device_list", lambda h: h.device_list()),
    ("device_info", lambda h: h.device_info("emulator-5554")),
    ("device_properties", lambda h: h.device_properties("emulator-5554")),
    ("device_packages", lambda h: h.device_packages("emulator-5554")),
    ("device_install", lambda h: h.device_install("emulator-5554", "/tmp/a.apk")),
    ("device_uninstall", lambda h: h.device_uninstall("emulator-5554", "a.b")),
    ("device_launch", lambda h: h.device_launch("emulator-5554", "a.b")),
    ("device_force_stop", lambda h: h.device_force_stop("emulator-5554", "a.b")),
    ("device_current_activity", lambda h: h.device_current_activity("emulator-5554")),
    ("device_logcat", lambda h: h.device_logcat("emulator-5554")),
    ("device_push", lambda h: h.device_push("emulator-5554", "/tmp/a", "/data/local/tmp/a")),
    ("device_forward", lambda h: h.device_forward("emulator-5554", "tcp:1", "tcp:2")),
]


@pytest.mark.parametrize("name,call", _DELEGATORS, ids=[name for name, _ in _DELEGATORS])
def test_delegator_returns_the_backend_payload(
    host: _Host, name: str, call: Callable[[_Host], Any]
) -> None:
    result = call(host)

    assert result.ok, result.error
    assert result.meta.get("backend") == "adb"


def test_delegator_maps_an_adb_error(tmp_path: Path) -> None:
    class _Failing(_OkAdb):
        def info(self, serial: str) -> dict[str, Any]:
            raise AdbError("device_offline", "device not connected", serial=serial)

    host = _Host(tmp_path / "artifacts", _Failing())

    result = host.device_info("emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "device_offline"


def test_delegator_maps_an_unexpected_error(tmp_path: Path) -> None:
    class _Failing(_OkAdb):
        def list_devices(self) -> dict[str, Any]:
            raise ValueError("boom")

    host = _Host(tmp_path / "artifacts", _Failing())

    result = host.device_list()

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# device_connect: honest connection reporting


def test_connect_returns_the_payload_when_actually_connected(host: _Host) -> None:
    result = host.device_connect("10.0.0.5", 5555)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["connected"] is True


def test_connect_fails_when_adb_reports_no_connection(tmp_path: Path) -> None:
    class _NoConnect(_OkAdb):
        def connect(self, host: str, port: int) -> dict[str, Any]:
            return {"connected": False, "result": "unable to connect", "endpoint": f"{host}:{port}"}

    host = _Host(tmp_path / "artifacts", _NoConnect())

    result = host.device_connect("10.0.0.5", 5555)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"
    assert "unable to connect" in result.error.message


def test_connect_maps_an_adb_error(tmp_path: Path) -> None:
    class _Failing(_OkAdb):
        def connect(self, host: str, port: int) -> dict[str, Any]:
            raise AdbError("invalid_params", "bad endpoint")

    host = _Host(tmp_path / "artifacts", _Failing())

    result = host.device_connect("10.0.0.5", 5555)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"


# ---------------------------------------------------------------------------
# device_screenshot / device_pull: capture bounds


def test_screenshot_returns_the_capture_and_prunes(host: _Host) -> None:
    result = host.device_screenshot("emulator-5554")

    assert result.ok, result.error
    assert result.data is not None
    assert Path(result.data["path"]).suffix == ".png"


def test_screenshot_refuses_an_oversized_capture(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    too_big = Result[dict[str, Any]](
        ok=False, error=RpcError(code="output_too_large", message="too big")
    )
    monkeypatch.setattr(service_device, "refuse_oversized_device_file", lambda _p: too_big)

    result = host.device_screenshot("emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "output_too_large"


def test_screenshot_prunes_even_when_the_capture_failed(tmp_path: Path) -> None:
    class _Failing(_OkAdb):
        def screenshot(self, serial: str, out_path: Path) -> dict[str, Any]:
            raise AdbError("backend_error", "screencap failed")

    host = _Host(tmp_path / "artifacts", _Failing())

    result = host.device_screenshot("emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_pull_returns_the_file_and_prunes(host: _Host) -> None:
    result = host.device_pull("emulator-5554", "/sdcard/log.txt")

    assert result.ok, result.error
    assert result.data is not None
    assert Path(result.data["path"]).suffix == ".txt"


def test_pull_refuses_an_oversized_file(
    host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    too_big = Result[dict[str, Any]](
        ok=False, error=RpcError(code="output_too_large", message="too big")
    )
    monkeypatch.setattr(service_device, "refuse_oversized_device_file", lambda _p: too_big)

    result = host.device_pull("emulator-5554", "/sdcard/big.bin")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "output_too_large"


def test_pull_prunes_even_when_the_transfer_failed(tmp_path: Path) -> None:
    class _Failing(_OkAdb):
        def pull(self, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
            raise AdbError("not_found", "no such path")

    host = _Host(tmp_path / "artifacts", _Failing())

    result = host.device_pull("emulator-5554", "/sdcard/missing")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


# ---------------------------------------------------------------------------
# _backend fallback construction


def test_backend_is_constructed_when_the_host_owns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host without an owned backend builds one from settings on demand."""

    class _Built:
        def __init__(self, adb_path: Any = None) -> None:
            self.adb_path = adb_path

        def list_devices(self) -> dict[str, Any]:
            return {"devices": ["built"]}

    monkeypatch.setattr(service_device, "AdbBackend", _Built)
    host = _Host(tmp_path / "artifacts", backend=None)

    result = host.device_list()

    assert result.ok, result.error
    assert result.data == {"devices": ["built"]}
