"""Branch coverage for the ADB device-control service mixin.

Device calls wrap AdbBackend into a Result: an AdbError becomes a structured
failure and an unexpected exception is still captured. adbutils returns a status
string for a failed connect instead of raising, so device.connect turns a
"connected: false" into an explicit failure. Unregistered captures (screenshot,
pull) are count-bounded and an over-cap pull is deleted after the fact and
reported. These fakes drive those branches without a device; the live gate pins
the real tool.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_device
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_device import (
    prune_device_artifacts,
    refuse_oversized_device_file,
)

MP = pytest.MonkeyPatch


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


class _FakeAdb:
    def list_devices(self) -> dict[str, Any]:
        return {"devices": [{"serial": "emulator-5554"}]}

    def connect(self, *, host: str, port: int) -> dict[str, Any]:
        return {"connected": True, "endpoint": f"{host}:{port}"}

    def info(self, *, serial: str) -> dict[str, Any]:
        return {"serial": serial}

    def screenshot(self, *, serial: str, out_path: Path) -> dict[str, Any]:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_bytes(b"\x89PNG")
        return {"path": str(out_path)}

    def pull(self, *, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        Path(local_path).write_bytes(b"payload")
        return {"path": str(local_path)}


def _use(service: AnalysisService, monkeypatch: MP, backend: Any) -> None:
    monkeypatch.setattr(service, "_backend", lambda: backend)


class TestPruneDeviceArtifacts:
    def test_ignores_a_missing_directory(self, tmp_path: Path) -> None:
        prune_device_artifacts(tmp_path / "nope")  # iterdir raises -> return

    def test_no_op_when_under_the_keep_bound(self, tmp_path: Path) -> None:
        for i in range(2):
            (tmp_path / f"f{i}.png").write_text("x")
        prune_device_artifacts(tmp_path, keep=8)
        assert len(list(tmp_path.iterdir())) == 2

    def test_survives_stat_errors_while_pruning(self, tmp_path: Path, monkeypatch: MP) -> None:
        for i in range(4):
            (tmp_path / f"f{i}.png").write_text("x")
        real_stat = Path.stat

        def _fake_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
            if sys._getframe(1).f_code.co_name == "_mtime":
                raise OSError("stat blew up")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _fake_stat)
        prune_device_artifacts(tmp_path, keep=1)
        assert len(list(tmp_path.iterdir())) == 1


class TestRefuseOversized:
    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert refuse_oversized_device_file(tmp_path / "gone.bin") is None

    def test_under_limit_returns_none(self, tmp_path: Path) -> None:
        target = tmp_path / "small.bin"
        target.write_bytes(b"tiny")
        assert refuse_oversized_device_file(target, limit=1024) is None

    def test_over_limit_deletes_and_reports(self, tmp_path: Path) -> None:
        target = tmp_path / "big.bin"
        target.write_bytes(b"x" * 64)
        result = refuse_oversized_device_file(target, limit=8)
        assert result is not None and result.ok is False
        assert result.error is not None and result.error.code == "output_too_large"
        assert not target.exists()


class _AllOps:
    """A backend that answers any op with an echo, for delegation coverage."""

    def __getattr__(self, name: str) -> Any:
        def _op(**kwargs: Any) -> dict[str, Any]:
            return {"op": name, **kwargs}

        return _op


class TestBackendResolution:
    def test_backend_falls_back_to_constructing_one(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        # A non-AdbBackend owned attribute forces the constructor path; with no
        # configured adb it degrades rather than crashing.
        monkeypatch.setattr(service, "_adb_backend", object(), raising=False)
        result = service.device_list()
        assert isinstance(result, Result)

    def test_backend_returns_the_owned_instance(self, service: AnalysisService) -> None:
        # The default AnalysisService owns a real AdbBackend; _backend returns it
        # (no configured adb, so the call itself degrades to a failure Result).
        result = service.device_list()
        assert isinstance(result, Result)


class TestDeviceOps:
    def test_device_list_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        _use(service, monkeypatch, _FakeAdb())
        result = service.device_list()
        assert result.ok is True and result.data is not None
        assert result.data["devices"][0]["serial"] == "emulator-5554"

    def test_connect_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        _use(service, monkeypatch, _FakeAdb())
        result = service.device_connect(host="10.0.0.2", port=5555)
        assert result.ok is True and result.data is not None
        assert result.data["connected"] is True

    def test_connect_reports_no_connection(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _NoConn(_FakeAdb):
            def connect(self, *, host: str, port: int) -> dict[str, Any]:
                return {"connected": False, "result": "unable to connect", "endpoint": "x"}

        _use(service, monkeypatch, _NoConn())
        result = service.device_connect()
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"
        assert "unable to connect" in result.error.message

    def test_connect_passes_a_backend_error_through(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Err(_FakeAdb):
            def connect(self, *, host: str, port: int) -> dict[str, Any]:
                raise AdbError("capability_unavailable", "no adb")

        _use(service, monkeypatch, _Err())
        result = service.device_connect()
        assert result.ok is False and result.error is not None
        assert result.error.code == "capability_unavailable"

    def test_wrap_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FakeAdb):
            def info(self, *, serial: str) -> dict[str, Any]:
                raise AdbError("not_found", "no such device")

        _use(service, monkeypatch, _Err())
        result = service.device_info("emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"

    def test_wrap_captures_unexpected(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Boom(_FakeAdb):
            def info(self, *, serial: str) -> dict[str, Any]:
                raise RuntimeError("boom")

        _use(service, monkeypatch, _Boom())
        assert service.device_info("emulator-5554").ok is False

    def test_all_simple_ops_delegate(self, service: AnalysisService, monkeypatch: MP) -> None:
        _use(service, monkeypatch, _AllOps())
        assert service.device_properties("s").ok is True
        assert service.device_packages("s", third_party_only=True).ok is True
        assert service.device_install("s", "/tmp/a.apk").ok is True
        assert service.device_uninstall("s", "com.x").ok is True
        assert service.device_launch("s", "com.x").ok is True
        assert service.device_force_stop("s", "com.x").ok is True
        assert service.device_current_activity("s").ok is True
        assert service.device_logcat("s").ok is True
        assert service.device_push("s", "/tmp/a", "/sdcard/a").ok is True
        assert service.device_forward("s", "tcp:1", "tcp:2").ok is True


class TestCaptures:
    def test_screenshot_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        _use(service, monkeypatch, _FakeAdb())
        result = service.device_screenshot("emulator-5554")
        assert result.ok is True and result.data is not None

    def test_screenshot_refuses_an_oversized_capture(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        _use(service, monkeypatch, _FakeAdb())
        too_big = Result[dict[str, Any]](
            ok=False, error=RpcError(code="output_too_large", message="too big")
        )
        monkeypatch.setattr(service_device, "refuse_oversized_device_file", lambda out: too_big)
        result = service.device_screenshot("emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "output_too_large"

    def test_screenshot_passes_a_backend_error_through(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Err(_FakeAdb):
            def screenshot(self, *, serial: str, out_path: Path) -> dict[str, Any]:
                raise AdbError("backend_error", "screencap failed")

        _use(service, monkeypatch, _Err())
        result = service.device_screenshot("emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_pull_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        _use(service, monkeypatch, _FakeAdb())
        result = service.device_pull("emulator-5554", "/sdcard/x.txt")
        assert result.ok is True and result.data is not None

    def test_pull_uses_bin_suffix_for_a_pathological_name(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        captured: dict[str, Any] = {}

        class _Capture(_FakeAdb):
            def pull(self, *, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
                captured["local"] = str(local_path)
                Path(local_path).parent.mkdir(parents=True, exist_ok=True)
                Path(local_path).write_bytes(b"x")
                return {"path": str(local_path)}

        _use(service, monkeypatch, _Capture())
        result = service.device_pull("emulator-5554", "/sdcard/no-extension")
        assert result.ok is True
        assert captured["local"].endswith(".bin")  # unsafe suffix fell back to .bin

    def test_pull_passes_a_backend_error_through(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Err(_FakeAdb):
            def pull(self, *, serial: str, remote_path: str, local_path: Path) -> dict[str, Any]:
                raise AdbError("not_found", "no such remote path")

        _use(service, monkeypatch, _Err())
        result = service.device_pull("emulator-5554", "/sdcard/missing")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"

    def test_pull_refuses_an_oversized_capture(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        _use(service, monkeypatch, _FakeAdb())
        too_big = Result[dict[str, Any]](
            ok=False, error=RpcError(code="output_too_large", message="too big")
        )
        monkeypatch.setattr(service_device, "refuse_oversized_device_file", lambda out: too_big)
        result = service.device_pull("emulator-5554", "/sdcard/big.bin")
        assert result.ok is False and result.error is not None
        assert result.error.code == "output_too_large"
