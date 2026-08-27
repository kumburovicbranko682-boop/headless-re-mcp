"""device.screenshot / device.pull write files retention cannot see."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core.limits import (
    UNREGISTERED_CAPTURE_MAX_ENTRIES,
    prune_capped_dir,
)
from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service_device import (
    DeviceAnalysisMixin,
    refuse_oversized_device_file,
)


def _fill(directory: Path, count: int, *, each: int) -> None:
    directory.mkdir(exist_ok=True)
    for index in range(count):
        path = directory / f"screenshot-{index:03d}.png"
        path.write_bytes(b"x" * each)
        # Distinct mtimes so "newest" is the highest index, not a tie.
        os.utime(path, (index + 1, index + 1))


def test_prune_keeps_only_the_newest_captures(tmp_path: Path) -> None:
    """The production prune (prune_capped_dir) drops the oldest by mtime.

    device.screenshot / device.pull retire the old count-only helper for the
    shared prune_capped_dir, so pin the behaviour the device directory relies
    on: the newest UNREGISTERED_CAPTURE_MAX_ENTRIES survive, oldest first.
    """
    directory = tmp_path / "device"
    _fill(directory, 80, each=256 * 1024)

    prune_capped_dir(
        directory,
        max_entries=UNREGISTERED_CAPTURE_MAX_ENTRIES,
        max_bytes=1 << 40,
    )

    left = sorted(path.name for path in directory.iterdir())
    assert len(left) == UNREGISTERED_CAPTURE_MAX_ENTRIES
    assert left[0] == "screenshot-048.png"
    assert left[-1] == "screenshot-079.png"
    total = sum(path.stat().st_size for path in directory.iterdir())
    assert total == UNREGISTERED_CAPTURE_MAX_ENTRIES * 256 * 1024


def test_prune_also_honours_the_byte_budget(tmp_path: Path) -> None:
    """When the byte cap bites before the count cap, it still keeps the newest."""
    directory = tmp_path / "device"
    _fill(directory, 20, each=256 * 1024)

    prune_capped_dir(directory, max_entries=1000, max_bytes=10 * 256 * 1024)

    left = sorted(path.name for path in directory.iterdir())
    assert len(left) == 10
    assert left[-1] == "screenshot-019.png"
    total = sum(path.stat().st_size for path in directory.iterdir())
    assert total <= 10 * 256 * 1024


class _Harness(DeviceAnalysisMixin):
    def __init__(self, root: Path) -> None:
        self.settings = SimpleNamespace(artifact_root=root)

    def _adb_wrap(self, op: str, /, **kwargs: object):  # type: ignore[override]
        path = Path(str(kwargs.get("out_path") or kwargs.get("local_path")))
        path.write_bytes(b"x" * 256 * 1024)
        return _success({"path": str(path)}, backend="adb")


def test_a_screenshot_loop_cannot_grow_the_device_directory_without_bound(
    tmp_path: Path,
) -> None:
    """80 shots of 256 KiB left 20.0 MiB. Retention never saw them.

    Device tools key by serial; the artifact table needs a session_id, so
    these files are not registered. The directory itself has to be the bound.
    """
    harness = _Harness(tmp_path)
    for _ in range(80):
        result = harness.device_screenshot("emulator-5554")
        assert result.ok is True

    directory = tmp_path / "device"
    files = list(directory.iterdir())
    assert len(files) == UNREGISTERED_CAPTURE_MAX_ENTRIES
    total = sum(path.stat().st_size for path in files)
    assert total == UNREGISTERED_CAPTURE_MAX_ENTRIES * 256 * 1024


@pytest.mark.parametrize(
    ("remote_path", "expected_suffix"),
    [
        ("/sdcard/report.txt", ".txt"),
        ("/sdcard/archive.tar.gz", ".gz"),
        ("/sdcard/report.txt:secret", ".bin"),
        ("/sdcard/report.txt\\secret", ".bin"),
        ("/sdcard/report." + "x" * 100, ".bin"),
        ("/sdcard/report.数据", ".bin"),
    ],
)
def test_device_pull_uses_only_portable_remote_suffixes(
    tmp_path: Path, remote_path: str, expected_suffix: str
) -> None:
    result = _Harness(tmp_path).device_pull("emulator-5554", remote_path)

    assert result.ok and result.data is not None, result.error
    local_path = Path(str(result.data["path"]))
    assert local_path.suffix == expected_suffix
    assert ":" not in local_path.name
    assert "\\" not in local_path.name


def test_device_capture_descriptions_do_not_call_the_file_an_artifact() -> None:
    """The tools return a bare path. Calling that an artifact sent the agent to artifacts.read."""
    from headless_re_mcp.tools.device import build_device_tools

    class _Dummy:
        def __getattr__(self, name: str):  # noqa: ANN204
            return lambda *args, **kwargs: None

    docs = {binding.name: binding.handler.__doc__ or "" for binding in build_device_tools(_Dummy())}  # type: ignore[arg-type]
    for name in ("device.screenshot", "device.pull"):
        text = docs[name]
        assert "not a registered artifact" in text
        assert "artifacts.read cannot open it" in text
        assert "newest 32" in text
        assert "64 MiB" in text
        assert "PNG artifact" not in text
        assert "local artifact" not in text


def test_a_device_file_over_the_byte_cap_is_deleted_and_refused(tmp_path: Path) -> None:
    """The count cap left each file unbounded. 32 huge pulls is still unbounded bytes."""
    path = tmp_path / "pull.bin"
    path.write_bytes(b"x" * 2048)
    refused = refuse_oversized_device_file(path, limit=1024)
    assert refused is not None
    assert refused.ok is False
    assert refused.error is not None
    assert refused.error.code == "output_too_large"
    assert path.exists() is False


def test_a_device_file_within_the_byte_cap_is_kept(tmp_path: Path) -> None:
    path = tmp_path / "shot.png"
    path.write_bytes(b"x" * 512)
    assert refuse_oversized_device_file(path, limit=1024) is None
    assert path.is_file()
