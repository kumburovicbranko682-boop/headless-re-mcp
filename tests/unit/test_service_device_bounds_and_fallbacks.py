"""Device capture bounds and backend fallbacks in the device.* service layer.

The device artifact directory is the one place retention never sees (captures
are keyed by serial, not session), so its own pruning and size refusal are the
only bounds it has. These tests pin the failure edges of that machinery -- a
directory that vanished, a file that vanished between listing and stat, a
capture the size check refuses after the fact -- plus the mixin's two backend
fallbacks: constructing an ad-hoc AdbBackend when none was injected, and
converting an unexpected exception into a failure envelope instead of letting
it escape the tool call.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_device
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

JsonObject = dict[str, Any]


class _Host(DeviceAnalysisMixin):
    def __init__(self, settings: Settings, backend: AdbBackend | None = None) -> None:
        self.settings = settings
        if backend is not None:
            self._adb_backend = backend


def _settings(tmp_path: Path) -> Settings:
    # Only artifact_root is consulted on these paths; the stand-in deliberately
    # has no adb attribute so _backend's getattr fallback is exercised too.
    return cast(Settings, SimpleNamespace(artifact_root=tmp_path))


def test_pruning_a_directory_that_vanished_is_a_no_op() -> None:
    prune_device_artifacts(Path("/nonexistent/device-artifacts"))


def test_pruning_under_the_cap_deletes_nothing(tmp_path: Path) -> None:
    keeper = tmp_path / "screenshot.png"
    keeper.write_bytes(b"png")

    prune_device_artifacts(tmp_path, keep=2)

    assert keeper.exists()


def test_a_file_that_vanishes_between_listing_and_stat_sorts_oldest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The race: iterdir saw the file, but by the time the sort asks for its
    # mtime it is gone. It must sort as oldest (mtime 0) and be pruned first
    # rather than aborting the sweep.
    vanished = tmp_path / "vanished.png"
    vanished.write_bytes(b"gone")
    old = tmp_path / "old.png"
    old.write_bytes(b"old")
    os.utime(old, (100, 100))
    new = tmp_path / "new.png"
    new.write_bytes(b"new")
    os.utime(new, (200, 200))

    real_stat = Path.stat
    real_is_file = Path.is_file

    def fake_is_file(self: Path, **kwargs: Any) -> bool:
        if self.name == "vanished.png":
            return True
        return real_is_file(self, **kwargs)

    def fake_stat(self: Path, **kwargs: Any) -> Any:
        if self.name == "vanished.png":
            raise OSError("deleted between listing and stat")
        return real_stat(self, **kwargs)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    monkeypatch.setattr(Path, "stat", fake_stat)

    prune_device_artifacts(tmp_path, keep=1)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["new.png"]


def test_refusing_a_capture_that_vanished_returns_none() -> None:
    assert refuse_oversized_device_file(Path("/nonexistent/pull.bin")) is None


def test_backend_is_constructed_ad_hoc_when_none_was_injected(tmp_path: Path) -> None:
    host = _Host(_settings(tmp_path))

    assert isinstance(host._backend(), AdbBackend)


def test_an_unexpected_backend_crash_becomes_a_failure_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def boom(**kwargs: Any) -> JsonObject:
        raise RuntimeError("adbutils fell over")

    monkeypatch.setattr(backend, "list_devices", boom)
    host = _Host(_settings(tmp_path), backend)

    result = host.device_list()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


def _refusal() -> Result[JsonObject]:
    return Result[JsonObject](
        ok=False,
        error=RpcError(code="output_too_large", message="capture over the limit"),
    )


def test_an_oversized_screenshot_is_refused_after_the_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def fake_screenshot(*, serial: str, out_path: Path) -> JsonObject:
        out_path.write_bytes(b"png")
        return {"path": str(out_path)}

    monkeypatch.setattr(backend, "screenshot", fake_screenshot)
    refusal = _refusal()
    monkeypatch.setattr(
        service_device,
        "refuse_oversized_device_file",
        lambda path, **kwargs: refusal,
    )
    host = _Host(_settings(tmp_path), backend)

    result = host.device_screenshot("emulator-5554")

    assert result is refusal


def test_an_oversized_pull_is_refused_after_the_prune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = AdbBackend()

    def fake_pull(*, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        local_path.write_bytes(b"blob")
        return {"path": str(local_path)}

    monkeypatch.setattr(backend, "pull", fake_pull)
    refusal = _refusal()
    monkeypatch.setattr(
        service_device,
        "refuse_oversized_device_file",
        lambda path, **kwargs: refusal,
    )
    host = _Host(_settings(tmp_path), backend)

    result = host.device_pull("emulator-5554", "/sdcard/app.apk")

    assert result is refusal
