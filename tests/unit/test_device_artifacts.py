"""device.screenshot / device.pull write files retention cannot see."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core.results import _success
from headless_re_mcp.core.service_device import (
    _MAX_DEVICE_ARTIFACTS,
    DeviceAnalysisMixin,
    prune_device_artifacts,
    refuse_oversized_device_file,
)


def test_prune_keeps_only_the_newest_captures(tmp_path: Path) -> None:
    directory = tmp_path / "device"
    directory.mkdir()
    for index in range(80):
        path = directory / f"screenshot-{index:03d}.png"
        path.write_bytes(b"x" * 256 * 1024)
        # Distinct mtimes so "newest" is the highest index, not a tie.
        os.utime(path, (index + 1, index + 1))

    prune_device_artifacts(directory, keep=32)

    left = sorted(path.name for path in directory.iterdir())
    assert len(left) == 32
    assert left[0] == "screenshot-048.png"
    assert left[-1] == "screenshot-079.png"
    total = sum(path.stat().st_size for path in directory.iterdir())
    assert total == 32 * 256 * 1024


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
    assert len(files) == _MAX_DEVICE_ARTIFACTS
    total = sum(path.stat().st_size for path in files)
    assert total == _MAX_DEVICE_ARTIFACTS * 256 * 1024


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


def _shrink_device_byte_cap(monkeypatch: pytest.MonkeyPatch, limit: int) -> None:
    """Drop the oversized-capture limit for the duration of one test.

    device_screenshot/device_pull call refuse_oversized_device_file(out) with
    no explicit limit, so it uses the module cap (64 MiB). Rather than write a
    64 MiB file, lower that default -- it lives in the function's keyword-only
    defaults dict, which monkeypatch.setitem restores after the test -- so the
    256 KiB the harness writes trips the real check through the real call site.
    """
    kwdefaults = refuse_oversized_device_file.__kwdefaults__
    assert kwdefaults is not None and "limit" in kwdefaults
    monkeypatch.setitem(kwdefaults, "limit", limit)


def test_device_screenshot_over_the_byte_cap_is_deleted_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service must honor the oversized check, not just define it.

    refuse_oversized_device_file is unit-tested in isolation, but nothing proved
    device_screenshot actually calls it and returns its refusal: a regression
    that dropped the check would leave the ok envelope pointing at a file too
    big to open, and the direct test of the helper would still pass. Drive the
    real call site with the harness writing 256 KiB against a 1 KiB cap.
    """
    _shrink_device_byte_cap(monkeypatch, 1024)
    harness = _Harness(tmp_path)

    result = harness.device_screenshot("emulator-5554")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "output_too_large"
    directory = tmp_path / "device"
    assert list(directory.iterdir()) == [], (
        "the oversized capture must be deleted, not left on disk"
    )


def test_device_pull_over_the_byte_cap_is_deleted_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pull path has its own copy of the oversized-capture branch (a pulled
    file is the higher-risk one: the remote path, not a fixed screenshot, sets
    the size), so it is pinned separately from screenshot."""
    _shrink_device_byte_cap(monkeypatch, 1024)
    harness = _Harness(tmp_path)

    result = harness.device_pull("emulator-5554", "/sdcard/big.bin")

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "output_too_large"
    directory = tmp_path / "device"
    assert list(directory.iterdir()) == []
