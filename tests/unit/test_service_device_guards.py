"""Retention helpers and oversize refusals of the ADB device service.

Device captures are keyed by serial, not session, so the artifact table never
sees them: the count/byte caps and the oversize refusal are the only things
standing between unattended pulls and unbounded disk growth.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.limits import MAX_MODULE_DUMP_BYTES
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    prune_device_artifacts,
    refuse_oversized_device_file,
)

JsonObject = dict[str, Any]


class _ScriptedAdb(AdbBackend):
    """AdbBackend double; a plain fake would fail the mixin's isinstance check."""

    def __init__(self) -> None:
        super().__init__(None)
        self.oversize = False
        self.fail_with: BaseException | None = None

    def _write(self, path: Path) -> None:
        path.write_bytes(b"capture")
        if self.oversize:
            # Sparse: st_size crosses the limit without writing 64 MiB.
            os.truncate(path, MAX_MODULE_DUMP_BYTES + 1)

    def list_devices(self) -> JsonObject:
        if self.fail_with is not None:
            raise self.fail_with
        return {"devices": [], "count": 0}

    def screenshot(self, serial: str, out_path: Path) -> JsonObject:
        if self.fail_with is not None:
            raise self.fail_with
        self._write(out_path)
        return {"serial": serial, "path": str(out_path)}

    def pull(self, serial: str, remote_path: str, local_path: Path) -> JsonObject:
        if self.fail_with is not None:
            raise self.fail_with
        self._write(local_path)
        return {"serial": serial, "remote_path": remote_path, "path": str(local_path)}


class _Service(DeviceAnalysisMixin):
    def __init__(self, artifact_root: Path, backend: AdbBackend | None = None) -> None:
        self.settings = Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
        )
        if backend is not None:
            self._adb_backend = backend


def _device_files(artifact_root: Path) -> list[Path]:
    directory = artifact_root / "device"
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.iterdir() if path.is_file())


def test_prune_returns_quietly_for_a_missing_directory(tmp_path: Path) -> None:
    prune_device_artifacts(tmp_path / "never-created")


def test_prune_leaves_a_directory_under_the_cap_alone(tmp_path: Path) -> None:
    keep_me = tmp_path / "capture.png"
    keep_me.write_bytes(b"1")

    prune_device_artifacts(tmp_path, keep=2)

    assert keep_me.is_file()


def test_prune_survives_a_capture_deleted_mid_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stat that races with deletion sorts as oldest instead of raising."""
    poison = tmp_path / "poison.bin"
    poison.write_bytes(b"1")
    middle = tmp_path / "middle.bin"
    middle.write_bytes(b"2")
    newest = tmp_path / "newest.bin"
    newest.write_bytes(b"3")
    os.utime(middle, ns=(1_000, 1_000))
    os.utime(newest, ns=(2_000, 2_000))
    # By real mtime the poisoned file is the newest; only the raced stat
    # (returning 0) can make it the one that gets pruned.
    os.utime(poison, ns=(3_000, 3_000))
    original_stat = Path.stat
    stat_calls = {"poison": 0}

    def racy_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.name == "poison.bin":
            stat_calls["poison"] += 1
            if stat_calls["poison"] > 1:
                raise OSError("stat raced with delete")
        return original_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", racy_stat)
    prune_device_artifacts(tmp_path, keep=2)
    monkeypatch.undo()

    assert not poison.exists()
    assert middle.is_file()
    assert newest.is_file()


def test_oversize_refusal_ignores_a_file_that_is_already_gone(tmp_path: Path) -> None:
    assert refuse_oversized_device_file(tmp_path / "never-written.bin") is None


def test_the_mixin_builds_a_fallback_backend_when_none_is_owned(tmp_path: Path) -> None:
    service = _Service(tmp_path)

    built = service._backend()

    assert isinstance(built, AdbBackend)
    assert built is not service._backend()  # a fresh one per call, nothing owned


def test_the_mixin_prefers_the_owned_backend(tmp_path: Path) -> None:
    owned = _ScriptedAdb()
    service = _Service(tmp_path, backend=owned)

    assert service._backend() is owned


def test_an_adb_refusal_keeps_its_structured_code(tmp_path: Path) -> None:
    backend = _ScriptedAdb()
    backend.fail_with = AdbError("device_not_found", "no such serial", serial="emulator-0")
    service = _Service(tmp_path, backend=backend)

    result = service.device_list()

    assert not result.ok and result.error is not None
    assert result.error.code == "device_not_found"
    assert result.error.details["serial"] == "emulator-0"


def test_an_unexpected_backend_error_still_answers_with_an_envelope(tmp_path: Path) -> None:
    backend = _ScriptedAdb()
    backend.fail_with = ValueError("adbutils answered garbage")
    service = _Service(tmp_path, backend=backend)

    result = service.device_list()

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"


def test_screenshot_keeps_a_capture_under_the_size_limit(tmp_path: Path) -> None:
    service = _Service(tmp_path, backend=_ScriptedAdb())

    result = service.device_screenshot("emulator-1")

    assert result.ok and result.data is not None
    files = _device_files(tmp_path)
    assert len(files) == 1
    assert files[0].suffix == ".png"


def test_screenshot_deletes_an_oversized_capture_and_says_so(tmp_path: Path) -> None:
    backend = _ScriptedAdb()
    backend.oversize = True
    service = _Service(tmp_path, backend=backend)

    result = service.device_screenshot("emulator-1")

    assert not result.ok and result.error is not None
    assert result.error.code == "output_too_large"
    assert result.error.details["size"] > MAX_MODULE_DUMP_BYTES
    assert _device_files(tmp_path) == []


def test_pull_deletes_an_oversized_file_and_says_so(tmp_path: Path) -> None:
    backend = _ScriptedAdb()
    backend.oversize = True
    service = _Service(tmp_path, backend=backend)

    result = service.device_pull("emulator-1", "/sdcard/huge.bin")

    assert not result.ok and result.error is not None
    assert result.error.code == "output_too_large"
    assert _device_files(tmp_path) == []


def test_a_failed_capture_skips_the_size_check_but_still_prunes(tmp_path: Path) -> None:
    backend = _ScriptedAdb()
    backend.fail_with = AdbError("device_not_found", "no such serial")
    service = _Service(tmp_path, backend=backend)

    screenshot = service.device_screenshot("emulator-1")
    pulled = service.device_pull("emulator-1", "/sdcard/f.bin")

    assert not screenshot.ok and screenshot.error is not None
    assert screenshot.error.code == "device_not_found"
    assert not pulled.ok and pulled.error is not None
    assert pulled.error.code == "device_not_found"
    assert _device_files(tmp_path) == []


def test_pull_keeps_a_small_file_with_a_safe_suffix(tmp_path: Path) -> None:
    service = _Service(tmp_path, backend=_ScriptedAdb())

    result = service.device_pull("emulator-1", "/sdcard/db.sqlite:evil$stream")

    assert result.ok
    files = _device_files(tmp_path)
    assert len(files) == 1
    assert files[0].suffix == ".bin"
