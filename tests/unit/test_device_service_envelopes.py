"""service_device's read passthroughs, backend fallback, and capture branches.

The audit tests pin every device mutation and capture provenance, and the
artifacts test pins the byte/count caps, but a few service-layer paths were
still untouched: the pure-read passthroughs (list/properties/packages/
current_activity), _adb_wrap's `except BaseException` catch-all, the _backend()
fallback that constructs an AdbBackend when the service owns none, the
AdbError arm of device.connect (which skips the connected-check downgrade), the
capture-failed branch that skips the oversize check, device.pull's oversize
refusal, and the two OSError guards plus the not-full early return in
prune_device_artifacts. A fake AdbBackend stands in so the service wiring is
what is exercised, without adbutils or a device.
"""

from __future__ import annotations

import os
import pathlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_device import DeviceAnalysisMixin, prune_device_artifacts

JsonObject = dict[str, Any]


class _FakeAdb(AdbBackend):
    """An AdbBackend stand-in with the read ops the audit fake lacked.

    Subclasses AdbBackend (adbutils absent just leaves it unavailable) so the
    mixin's isinstance check in _backend() accepts it. ``fail`` raises AdbError
    for an op; ``crash`` raises a non-AdbError to drive the catch-all.
    """

    def __init__(self) -> None:
        super().__init__()
        self.fail: set[str] = set()
        self.crash: set[str] = set()

    def _guard(self, op: str) -> None:
        if op in self.crash:
            raise RuntimeError(f"{op} crashed")
        if op in self.fail:
            raise AdbError("backend_error", f"{op} failed")

    def list_devices(self) -> JsonObject:
        self._guard("list_devices")
        return {"devices": [], "count": 0}

    def info(self, serial: str) -> JsonObject:
        self._guard("info")
        return {"serial": serial, "state": "device"}

    def properties(self, serial: str, limit: int = 500) -> JsonObject:
        self._guard("properties")
        return {"properties": {}, "count": 0}

    def packages(self, serial: str, third_party_only: bool = False, limit: int = 500) -> JsonObject:
        self._guard("packages")
        return {"packages": [], "count": 0}

    def current_activity(self, serial: str) -> JsonObject:
        self._guard("current_activity")
        return {"activity": "com.example/.Main"}

    def logcat(self, serial: str, lines: int = 200) -> JsonObject:
        self._guard("logcat")
        return {"lines": [], "count": 0, "requested": lines, "truncated": False}

    def connect(self, host: str = "127.0.0.1", port: int = 5555) -> JsonObject:
        self._guard("connect")
        return {"endpoint": f"{host}:{port}", "result": "connected", "connected": True}

    def screenshot(self, serial: str, out_path: Any) -> JsonObject:
        self._guard("screenshot")
        Path(out_path).write_bytes(b"\x89PNG")
        return {"path": str(out_path), "serial": serial, "size": 4}

    def pull(self, serial: str, remote_path: str, local_path: Any) -> JsonObject:
        self._guard("pull")
        Path(local_path).write_bytes(b"data")
        return {"remote": remote_path, "local": str(local_path), "size": 4}


def _service(tmp_path: Path) -> tuple[AnalysisService, _FakeAdb]:
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    fake = _FakeAdb()
    service._adb_backend = fake
    return service, fake


def _audit_actions(service: AnalysisService) -> list[str]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return [str(e["action"]) for e in result.data["entries"]]


def test_pure_read_passthroughs_wrap_and_are_not_audited(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        for result in (
            service.device_list(),
            service.device_info("emulator-5554"),
            service.device_properties("emulator-5554"),
            service.device_packages("emulator-5554"),
            service.device_current_activity("emulator-5554"),
            service.device_logcat("emulator-5554"),
        ):
            assert result.ok is True, result.error
            assert result.meta.get("backend") == "adb"
        # Pure reads touch nothing, so none of them leave an audit entry.
        assert _audit_actions(service) == []
    finally:
        service.close_all()


def test_a_read_maps_a_backend_error(tmp_path: Path) -> None:
    service, fake = _service(tmp_path)
    try:
        fake.fail.add("list_devices")
        result = service.device_list()
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_adb_wrap_fails_closed_on_an_unexpected_fault(tmp_path: Path) -> None:
    """A non-AdbError from a backend op must become a structured internal_error,
    not escape _adb_wrap into the RPC loop."""
    service, fake = _service(tmp_path)
    try:
        fake.crash.add("info")
        result = service.device_info("emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_backend_falls_back_to_constructing_an_adb_backend(tmp_path: Path) -> None:
    """When the mixin owns no AdbBackend, _backend() builds one from settings
    rather than failing -- the standalone (non-AnalysisService) path."""

    class _MiniHarness(DeviceAnalysisMixin):
        def __init__(self, root: Path) -> None:
            self.settings = SimpleNamespace(artifact_root=root, adb=None)  # type: ignore[assignment]

    harness = _MiniHarness(tmp_path)
    assert isinstance(harness._backend(), AdbBackend)


def test_device_connect_backend_error_skips_the_downgrade_and_audits(tmp_path: Path) -> None:
    """An adb-level connect failure (an exception, not a not-connected reply)
    goes straight to the failure envelope without the connected-check block, and
    is still audited with its code."""
    service, fake = _service(tmp_path)
    try:
        fake.fail.add("connect")
        result = service.device_connect("127.0.0.1", 5555)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"

        rows = service.audit_list(None)
        assert rows.ok and rows.data is not None
        connect_rows = [e for e in rows.data["entries"] if e["action"] == "device.connect"]
        assert connect_rows and connect_rows[0]["ok"] == 0
        assert connect_rows[0]["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()


def test_a_failed_capture_skips_the_oversize_check_and_audits_the_failure(
    tmp_path: Path,
) -> None:
    service, fake = _service(tmp_path)
    try:
        fake.fail.add("screenshot")
        shot = service.device_screenshot("emulator-5554")
        assert shot.ok is False
        assert shot.error is not None and shot.error.code == "backend_error"

        fake.fail.add("pull")
        pulled = service.device_pull("emulator-5554", "/sdcard/f.bin")
        assert pulled.ok is False
        assert pulled.error is not None and pulled.error.code == "backend_error"

        actions = _audit_actions(service)
        assert "device.screenshot" in actions
        assert "device.pull" in actions
    finally:
        service.close_all()


def test_device_pull_over_the_cap_is_refused_and_audited_as_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pull that hit disk, exceeded the cap and was deleted must report and
    audit the too_large outcome, not the raw ok the backend first returned."""
    service, _ = _service(tmp_path)
    try:
        monkeypatch.setattr(
            "headless_re_mcp.core.service_device.refuse_oversized_device_file",
            lambda out: Result(
                ok=False,
                error=RpcError(code="output_too_large", message="too big", details={}),
            ),
        )
        result = service.device_pull("emulator-5554", "/sdcard/big.bin")
        assert result.ok is False
        assert result.error is not None and result.error.code == "output_too_large"

        rows = service.audit_list(None)
        assert rows.ok and rows.data is not None
        pull_rows = [e for e in rows.data["entries"] if e["action"] == "device.pull"]
        assert pull_rows and pull_rows[0]["result_summary"] == {"code": "output_too_large"}
    finally:
        service.close_all()


def test_prune_returns_on_a_non_directory(tmp_path: Path) -> None:
    """iterdir on a file raises OSError; the pruner must swallow it and return."""
    not_a_dir = tmp_path / "regular-file"
    not_a_dir.write_text("x", encoding="utf-8")
    prune_device_artifacts(not_a_dir)


def test_prune_is_a_no_op_when_the_directory_is_not_full(tmp_path: Path) -> None:
    directory = tmp_path / "device"
    directory.mkdir()
    for index in range(3):
        (directory / f"screenshot-{index}.png").write_bytes(b"x")

    prune_device_artifacts(directory, keep=32)

    assert len(os.listdir(directory)) == 3


def test_prune_survives_stat_failures_while_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a capture vanishes between the is_file filter and the mtime sort, its
    stat raises; _mtime treats that as age 0 so the sweep still trims to keep."""
    directory = tmp_path / "device"
    directory.mkdir()
    for index in range(3):
        (directory / f"screenshot-{index}.png").write_bytes(b"x")

    monkeypatch.setattr(pathlib.Path, "is_file", lambda self: self.name.endswith(".png"))

    def _stat_is_down(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        raise OSError("stat is down")

    monkeypatch.setattr(pathlib.Path, "stat", _stat_is_down)

    prune_device_artifacts(directory, keep=1)

    assert len(os.listdir(directory)) == 1
