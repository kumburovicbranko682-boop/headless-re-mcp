"""ADB device-control service-layer paths (DeviceAnalysisMixin).

The AdbBackend is exercised directly elsewhere; here the service orchestration is
pinned: the _adb_wrap fan-out across every device.* op, connect's honesty guard
(adbutils returns a status string rather than raising), the screenshot/pull
capture bounds (oversized deletion and directory pruning), and the pure capture
helpers. A fake AdbBackend subclass keeps the _backend() isinstance gate happy
while replacing the device I/O.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_device
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_device import (
    _safe_pull_suffix,
    prune_device_artifacts,
    refuse_oversized_device_file,
)


class _FakeAdb(AdbBackend):
    def __init__(self) -> None:
        super().__init__()
        self.raise_on: dict[str, BaseException] = {}
        self.connected: bool = True

    def _maybe(self, op: str) -> None:
        exc = self.raise_on.get(op)
        if exc is not None:
            raise exc

    def list_devices(self) -> dict[str, Any]:
        self._maybe("list_devices")
        return {"devices": [], "count": 0}

    def connect(self, host: str = "127.0.0.1", port: int = 5555) -> dict[str, Any]:
        self._maybe("connect")
        return {
            "connected": self.connected,
            "endpoint": f"{host}:{port}",
            "result": "connected" if self.connected else "unable to connect",
        }

    def info(self, serial: str) -> dict[str, Any]:
        self._maybe("info")
        return {"serial": serial, "model": "Pixel"}

    def properties(self, serial: str, limit: int = 500) -> dict[str, Any]:
        self._maybe("properties")
        return {"properties": {}, "count": 0}

    def packages(
        self, serial: str, third_party_only: bool = False, limit: int = 500
    ) -> dict[str, Any]:
        self._maybe("packages")
        return {"packages": [], "count": 0}

    def install(self, serial: str, apk_path: str, reinstall: bool = True) -> dict[str, Any]:
        self._maybe("install")
        return {"installed": True}

    def uninstall(self, serial: str, package: str) -> dict[str, Any]:
        self._maybe("uninstall")
        return {"uninstalled": True}

    def launch(self, serial: str, package: str) -> dict[str, Any]:
        self._maybe("launch")
        return {"launched": package}

    def force_stop(self, serial: str, package: str) -> dict[str, Any]:
        self._maybe("force_stop")
        return {"stopped": package}

    def current_activity(self, serial: str) -> dict[str, Any]:
        self._maybe("current_activity")
        return {"activity": "com.example/.Main"}

    def logcat(self, serial: str, lines: int = 200) -> dict[str, Any]:
        self._maybe("logcat")
        return {"lines": [], "count": 0}

    def screenshot(self, serial: str, out_path: Path) -> dict[str, Any]:
        self._maybe("screenshot")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_bytes(b"\x89PNG\r\n\x1a\n" + b"pixels")
        return {"path": str(out_path), "size": Path(out_path).stat().st_size}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
        self._maybe("pull")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_bytes(b"remote bytes")
        return {"path": str(local_path), "size": Path(local_path).stat().st_size}

    def push(self, serial: str, local_path: str, remote_path: str) -> dict[str, Any]:
        self._maybe("push")
        return {"pushed": remote_path}

    def forward(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        self._maybe("forward")
        return {"local": local, "remote": remote}


def _service(tmp_path: Path) -> tuple[AnalysisService, _FakeAdb]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeAdb()
    service._adb_backend = fake
    return service, fake


# ---------------------------------------------------------------------------
# pure capture helpers
# ---------------------------------------------------------------------------
def test_safe_pull_suffix_keeps_a_clean_extension_and_falls_back() -> None:
    assert _safe_pull_suffix("/sdcard/log.txt") == ".txt"
    assert _safe_pull_suffix("/sdcard/archive.tar.gz") == ".gz"
    assert _safe_pull_suffix("/sdcard/noext") == ".bin"
    assert _safe_pull_suffix("/sdcard/weird.name space") == ".bin"
    assert _safe_pull_suffix("/sdcard/a.verylongextensionhere") == ".bin"


def test_prune_device_artifacts_drops_the_oldest(tmp_path: Path) -> None:
    for i in range(5):
        f = tmp_path / f"cap{i}.png"
        f.write_bytes(b"x")
        import os

        os.utime(f, ns=(1000 + i, 1000 + i))
    prune_device_artifacts(tmp_path, keep=2)
    remaining = sorted(p.name for p in tmp_path.iterdir())
    assert remaining == ["cap3.png", "cap4.png"]


def test_prune_device_artifacts_tolerates_a_missing_directory(tmp_path: Path) -> None:
    prune_device_artifacts(tmp_path / "does-not-exist", keep=2)  # no raise


def test_refuse_oversized_device_file(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"a" * 4)
    assert refuse_oversized_device_file(small, limit=100) is None
    assert small.is_file()

    big = tmp_path / "big.bin"
    big.write_bytes(b"a" * 40)
    refused = refuse_oversized_device_file(big, limit=8)
    assert refused is not None and refused.error is not None
    assert refused.error.code == "output_too_large"
    assert not big.exists()

    assert refuse_oversized_device_file(tmp_path / "gone.bin", limit=8) is None


# ---------------------------------------------------------------------------
# device.* ops via _adb_wrap
# ---------------------------------------------------------------------------
def test_device_read_and_action_ops_succeed(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        assert service.device_list().ok
        assert service.device_info("emulator-5554").ok
        assert service.device_properties("emulator-5554", limit=10).ok
        assert service.device_packages("emulator-5554", third_party_only=True, limit=10).ok
        assert service.device_install("emulator-5554", "/tmp/a.apk").ok
        assert service.device_uninstall("emulator-5554", "com.x").ok
        assert service.device_launch("emulator-5554", "com.x").ok
        assert service.device_force_stop("emulator-5554", "com.x").ok
        assert service.device_current_activity("emulator-5554").ok
        assert service.device_logcat("emulator-5554", lines=10).ok
        assert service.device_push("emulator-5554", "/tmp/f", "/sdcard/f").ok
        assert service.device_forward("emulator-5554", "tcp:8080", "tcp:8080").ok
    finally:
        service.close_all()


def test_device_wrap_maps_adb_error_and_unexpected(tmp_path: Path) -> None:
    service, fake = _service(tmp_path)
    try:
        fake.raise_on["info"] = AdbError("not_found", "no such device")
        mapped = service.device_info("emulator-5554")
        assert mapped.ok is False
        assert mapped.error is not None and mapped.error.code == "not_found"

        fake.raise_on["logcat"] = RuntimeError("pipe exploded")
        unexpected = service.device_logcat("emulator-5554")
        assert unexpected.ok is False
        assert unexpected.error is not None and unexpected.error.code == "internal_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# device_connect honesty guard
# ---------------------------------------------------------------------------
def test_device_connect_success(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        result = service.device_connect(port=5556)
        assert result.ok, result.error
        assert result.data is not None and result.data["connected"] is True
    finally:
        service.close_all()


def test_device_connect_reports_a_failed_connection(tmp_path: Path) -> None:
    service, fake = _service(tmp_path)
    fake.connected = False
    try:
        result = service.device_connect()
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
        assert "connect failed" in result.error.message
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# device_screenshot / device_pull capture bounds
# ---------------------------------------------------------------------------
def test_device_screenshot_success_writes_and_prunes(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        result = service.device_screenshot("emulator-5554")
        assert result.ok, result.error
        assert result.data is not None and Path(result.data["path"]).is_file()
    finally:
        service.close_all()


def test_device_screenshot_refuses_an_oversized_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = service_device.refuse_oversized_device_file
    monkeypatch.setattr(
        service_device, "refuse_oversized_device_file", lambda p, **k: real(p, limit=4)
    )
    service, _fake = _service(tmp_path)
    try:
        result = service.device_screenshot("emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "output_too_large"
    finally:
        service.close_all()


def test_device_pull_success_uses_a_safe_suffix(tmp_path: Path) -> None:
    service, _fake = _service(tmp_path)
    try:
        result = service.device_pull("emulator-5554", "/sdcard/data.db")
        assert result.ok, result.error
        assert result.data is not None
        assert Path(result.data["path"]).suffix == ".db"
    finally:
        service.close_all()


def test_device_pull_refuses_an_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = service_device.refuse_oversized_device_file
    monkeypatch.setattr(
        service_device, "refuse_oversized_device_file", lambda p, **k: real(p, limit=4)
    )
    service, _fake = _service(tmp_path)
    try:
        result = service.device_pull("emulator-5554", "/sdcard/big.bin")
        assert result.ok is False
        assert result.error is not None and result.error.code == "output_too_large"
    finally:
        service.close_all()


def test_device_pull_maps_adb_error(tmp_path: Path) -> None:
    service, fake = _service(tmp_path)
    fake.raise_on["pull"] = AdbError("too_large", "file over cap")
    try:
        result = service.device_pull("emulator-5554", "/sdcard/x")
        assert result.ok is False
        assert result.error is not None and result.error.code == "too_large"
    finally:
        service.close_all()
