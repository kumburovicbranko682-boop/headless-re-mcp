"""Edge paths of device capture retention, oversize refusal, and error wrapping."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    JsonObject,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

# ---------------------------------------------------------------------------
# prune_device_artifacts


def test_prune_of_a_missing_directory_is_a_quiet_no_op(tmp_path: Path) -> None:
    prune_device_artifacts(tmp_path / "never-created")


def test_prune_under_the_cap_deletes_nothing(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"shot-{index}.png").write_bytes(b"x")

    prune_device_artifacts(tmp_path, keep=32)

    assert len(list(tmp_path.iterdir())) == 3


def test_prune_treats_an_unstattable_file_as_oldest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A capture whose mtime lookup fails sorts first and is dropped."""
    doomed = tmp_path / "doomed.png"
    doomed.write_bytes(b"x")
    survivor = tmp_path / "survivor.png"
    survivor.write_bytes(b"x")
    os.utime(survivor, (1, 1))

    real_stat = Path.stat
    calls = {"doomed": 0}

    def flaky_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.name == "doomed.png":
            calls["doomed"] += 1
            # First stat is the is_file() probe; the second is _mtime().
            if calls["doomed"] >= 2:
                raise OSError("stat refused")
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    prune_device_artifacts(tmp_path, keep=1)
    monkeypatch.undo()

    assert not doomed.exists()
    assert survivor.exists()


# ---------------------------------------------------------------------------
# refuse_oversized_device_file


def test_a_vanished_capture_is_not_refused(tmp_path: Path) -> None:
    assert refuse_oversized_device_file(tmp_path / "gone.bin", limit=1) is None


# ---------------------------------------------------------------------------
# _backend fallback and _adb_wrap error mapping


class _BareHost(DeviceAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root, adb=None)  # type: ignore[assignment]


def test_backend_is_constructed_when_the_service_owns_none(tmp_path: Path) -> None:
    host = _BareHost(tmp_path)
    assert isinstance(host._backend(), AdbBackend)


def test_a_non_backend_attribute_is_not_trusted_as_the_backend(tmp_path: Path) -> None:
    host = _BareHost(tmp_path)
    host._adb_backend = object()  # type: ignore[assignment]
    assert isinstance(host._backend(), AdbBackend)


class _FakeAdb:
    def list_devices(self) -> JsonObject:
        raise RuntimeError("adb server exploded")

    def info(self, serial: str) -> JsonObject:
        raise AdbError("device_not_found", f"no device {serial}", serial=serial)


def _host_with_fake(tmp_path: Path) -> _BareHost:
    host = _BareHost(tmp_path)
    fake = _FakeAdb()
    host._backend = lambda: fake  # type: ignore[method-assign, assignment, return-value]
    return host


def test_an_unexpected_backend_crash_becomes_a_failure_envelope(tmp_path: Path) -> None:
    result = _host_with_fake(tmp_path).device_list()

    assert result.ok is False
    assert result.error is not None
    assert "adb server exploded" in result.error.message


def test_an_adb_error_keeps_its_code_and_details(tmp_path: Path) -> None:
    result = _host_with_fake(tmp_path).device_info("emulator-5554")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "device_not_found"
    assert result.error.details.get("serial") == "emulator-5554"


# ---------------------------------------------------------------------------
# oversized screenshot / pull refusal still prunes the directory


class _CapturingHost(DeviceAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root)  # type: ignore[assignment]

    def _adb_wrap(self, op: str, /, **kwargs: Any) -> Result[JsonObject]:
        path = Path(str(kwargs.get("out_path") or kwargs.get("local_path")))
        path.write_bytes(b"x" * 64)
        return _success({"path": str(path)}, backend="adb")


def _refusal(path: Path) -> Result[JsonObject]:
    return Result[JsonObject](
        ok=False,
        error=RpcError(code="output_too_large", message="too big", details={}),
    )


@pytest.mark.parametrize("tool", ["device_screenshot", "device_pull"])
def test_an_oversized_capture_is_refused_and_the_directory_still_pruned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    import headless_re_mcp.core.service_device as service_device

    monkeypatch.setattr(service_device, "refuse_oversized_device_file", _refusal)
    pruned: list[Path] = []

    def spy_prune(directory: Path, **kwargs: Any) -> None:
        pruned.append(directory)

    monkeypatch.setattr(service_device, "prune_capped_dir", spy_prune)

    host = _CapturingHost(tmp_path)
    if tool == "device_screenshot":
        result = host.device_screenshot("emulator-5554")
    else:
        result = host.device_pull("emulator-5554", "/sdcard/huge.bin")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "output_too_large"
    assert pruned == [tmp_path / "device"]
